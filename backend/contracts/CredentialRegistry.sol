// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CredentialRegistry
 * @dev Registro inmutable para el anclaje de firmas y hashes de Microcredenciales W3C (SD-JWT).
 * Provee prueba de existencia, validez y revocación gestionada por la universidad emisora (Owner).
 */
contract CredentialRegistry {
    address public owner;

    enum CredentialState {
        NotIssued,
        Valid,
        Revoked
    }

    struct RegistryEntry {
        CredentialState state;
        uint256 timestamp;
        string courseName; // Metadato on-chain para análisis y block explorers
    }

    mapping(bytes32 => RegistryEntry) public credentials;

    // Eventos para indexadores (Blockscout, Etherscan)
    event CredentialIssued(bytes32 indexed credentialHash, uint256 timestamp, string courseName);
    event CredentialRevoked(bytes32 indexed credentialHash, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "Error: Revertido. Acceso denegado, entidad no autorizada.");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Registra de manera pública e inmutable la huella digital (Hash) de un certificado emitido
     * @param hash El SHA-256 de la credencial firmada SD-JWT original
     * @param courseName Nombre del curso (sirve para transparencia de emisión on-chain)
     */
    function issueCredential(bytes32 hash, string memory courseName) public onlyOwner {
        require(credentials[hash].state == CredentialState.NotIssued, "Error: La credencial ya se encuentra registrada en la Mainnet/Testnet.");
        
        credentials[hash] = RegistryEntry({
            state: CredentialState.Valid,
            timestamp: block.timestamp,
            courseName: courseName
        });

        emit CredentialIssued(hash, block.timestamp, courseName);
    }

    /**
     * @notice Revoca categóricamente la validez del Hash, impidiendo que el portal web muestre la credencial como válida
     * @param hash El SHA-256 a revocar
     */
    function revokeCredential(bytes32 hash) public onlyOwner {
        require(credentials[hash].state == CredentialState.Valid, "Error: La credencial no existe o ya ha sido neutralizada.");

        credentials[hash].state = CredentialState.Revoked;
        credentials[hash].timestamp = block.timestamp;
        
        emit CredentialRevoked(hash, block.timestamp);
    }

    /**
     * @notice Consulta pública (Read-Only) para verificadores web y portales de RRHH
     * @param hash El SHA-256 a verificar
     * @return bool True si es válida, False si fue alterada, forjada o revocada
     */
    function isValid(bytes32 hash) public view returns (bool) {
        return credentials[hash].state == CredentialState.Valid;
    }
}
