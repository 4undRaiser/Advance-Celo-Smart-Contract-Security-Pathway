// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract CELO_POLYGON_Bridge is Ownable {
    IERC20 public celo;
    address public celoAddress;
    mapping(bytes32 => bool) public usedNonces;
    mapping(address => uint256) public lockedTokens;
    uint256 public lockTime;
    uint256 public unlockTime;
    address[] public signers;
    mapping(address => bool) public authorized;

    event Locked(
        address indexed sender,
        uint256 indexed amount,
        bytes32 indexed nonce,
        uint256 lockTime
    );
    event Unlocked(
        address indexed recipient,
        uint256 indexed amount,
        uint256 unlockTime
    );

    constructor(
        address _celoAddress,
        uint256 _lockTime,
        uint256 _unlockTime,
        address[] memory _signers
    ) {
        celo = IERC20(_celoAddress);
        celoAddress = _celoAddress;
        lockTime = _lockTime;
        unlockTime = _unlockTime;
        signers = _signers;

        for (uint256 i = 0; i < signers.length; i++) {
            authorized[signers[i]] = true;
        }
    }

    function lock(uint256 amount, bytes32 nonce) public {
        require(amount > 0, "Amount must be greater than 0");
        require(!usedNonces[nonce], "Nonce has already been used");

        bool success = celo.transferFrom(msg.sender, address(this), amount);
        require(success, "Transfer failed");

        usedNonces[nonce] = true;
        lockedTokens[msg.sender] += amount;
        emit Locked(msg.sender, amount, nonce, block.timestamp + lockTime);
    }

    function unlock(
        address recipient,
        uint256 amount,
        bytes memory signature,
        bytes32 nonce
    ) public {
        require(amount > 0, "Amount must be greater than 0");

        bytes32 message = keccak256(
            abi.encodePacked(recipient, amount, nonce, usedNonces[nonce])
        );
        bytes32 hash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", message)
        );
        address signer = recover(hash, signature);

        require(authorized[signer], "Invalid signature");
        require(block.timestamp <= unlockTime, "Unlocking period has ended");
        require(!usedNonces[nonce], "Nonce has already been used");

        usedNonces[nonce] = true;
        bool success = celo.transfer(recipient, amount);
        require(success, "Transfer failed");

        emit Unlocked(recipient, amount, block.timestamp + unlockTime);
    }

    function claimLockedTokens() public {
        require(
            block.timestamp >= lockedTokens[msg.sender],
            "Tokens are not yet unlocked"
        );

        uint256 amount = lockedTokens[msg.sender];
        lockedTokens[msg.sender] = 0;

        bool success = celo.transfer(msg.sender, amount);
        require(success, "Transfer failed");
    }

    function recover(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        if (signature.length != 65) {
            return address(0);
        }

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        if (v != 27 && v != 28) {
            return address(0);
        } else {
            return ecrecover(hash, v, r, s);
        }
    }
}
