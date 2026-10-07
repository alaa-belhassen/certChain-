// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./AccessControl.sol";

interface ICertificateNFT {
    function mint(address to, uint256 tokenId) external;
    function burn(uint256 tokenId) external;
}

contract CertificateRegistry is AccessControl {
    struct Certificate {
        address issuer;
        address student;
        string degree;        
        uint16 year;        
        string metadataURI;  
        uint256 issuedAt;
        bool revoked;
    }
    uint256 private nonce = 0;
    mapping(address => bytes32[]) private studentCertificates;
    mapping(bytes32 => Certificate) private certificates;
    ICertificateNFT public nft; // optional

    event CertificateIssued(bytes32 indexed hash, address indexed issuer, address indexed student);
    event CertificateRevoked(bytes32 indexed hash, address indexed by);
    event CertificateVerified(bytes32 indexed hash, address indexed verifier, bool valid);
    event CertificateCreated(bytes32 indexed hash, address indexed creator, bool valid);

    function setNFT(address nftAddress) external onlyAdmin {
        nft = ICertificateNFT(nftAddress);
    }

    function createCertificate(
    address student,
    string calldata degree,
    uint16 year,
    string calldata metadataURI) external onlyIssuer returns (bytes32 hash) {
        require(student != address(0), "Zero address");
        require(year > 2020, "year inferior 2020 ");
        require(bytes(metadataURI).length > 0, "meta data is required");
        _requireNamed(student, "Student has no name"); 
        _requireNamed(msg.sender, "Issuer has no name"); 
        require(bytes(degree).length > 0, "Empty degree");
        nonce ++ ;
        
        hash = keccak256(
         abi.encode(student, degree, year, msg.sender, block.timestamp, nonce)
        );
        require( certificates[hash].issuedAt == 0 , "Already issued");

        certificates[hash] = Certificate(
         msg.sender, student, degree, year,metadataURI, block.timestamp, false
        );
        emit CertificateCreated(hash, msg.sender, true);

        return hash;
    }
    
    // Issue: store the hash of the diploma file (computed off-chain)
    function issueCertificate(bytes32 hash, address student) external onlyIssuer {
        require(hash != bytes32(0), "Empty hash");
        require(certificates[hash].issuedAt > 0, "Certificate does not exist");
        require(certificates[hash].student == student, "Student mismatch"); 
        require(certificates[hash].issuer == msg.sender, "Issuer mismatch"); // verifie issuer is certificate creator 
        _requireNamed(student, "Student has no name"); 
        _requireNamed(msg.sender, "Issuer has no name"); 
        studentCertificates[student].push(hash);
       
        if (address(nft) != address(0)) {
            nft.mint(student, uint256(hash));
        }

        emit CertificateIssued(hash, msg.sender, student);
    }
    function getCertificatesOf(address student, bool revoked) external view returns (bytes32[] memory) {
        bytes32[] storage all = studentCertificates[student];

        // Pass 1: count the matches
        uint256 count = 0;
        for (uint256 i = 0; i < all.length; i++) {
            if (certificates[all[i]].revoked == revoked) {
                count++;
            }
        }
        // Pass 2: fill the result array
        bytes32[] memory result = new bytes32[](count);
        uint256 index = 0;
        for (uint256 i = 0; i < all.length; i++) {
            if (certificates[all[i]].revoked == revoked) {
                result[index] = all[i];
                index++;
            }
        }
        return result;
    }
    // Revoke: only the issuer who issued it, or the admin
    function revokeCertificate(bytes32 hash) external {
        Certificate storage c = certificates[hash];
        require(c.issuedAt != 0, "Not found");
        require(!c.revoked, "Already revoked");
        require(
            msg.sender == c.issuer || roles[msg.sender] == Role.Admin,
            "Not allowed"
        );

        c.revoked = true;

        if (address(nft) != address(0)) {
            nft.burn(uint256(hash));
        }
        emit CertificateRevoked(hash, msg.sender);
    }

    // Free and public: anyone can check
    function verifyCertificate(bytes32 hash)
        public
        view
        returns (bool valid, address issuer, uint256 issuedAt)
    {
        Certificate memory c = certificates[hash];
        return (c.issuedAt != 0 && !c.revoked, c.issuer, c.issuedAt);
    }

    // Optional: gives the Verifier role a purpose by leaving an on-chain trace
    function logVerification(bytes32 hash) external onlyVerifier {
        (bool valid, , ) = verifyCertificate(hash);
        emit CertificateVerified(hash, msg.sender, valid);
    }
}