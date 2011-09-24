package com.mattbertolini.antpgp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * 
 * @author Matt Bertolini
 */
public interface PgpSignatureGenerator {
    /**
     * Initializes the signature generator with the given PGP secret keyring file, key ID, and passphrase. The 
     * signature generator cannot be used until the initialization has occurred.
     * @param secretKeyring The PGP secret keyring file containing a key matching the key id.
     * @param keyId The key id to look for in the keyring file.
     * @param passphrase The passphrase of the key in the keyring file.
     * @throws FileNotFoundException If the secret keyring file is not found.
     * @throws IOException
     * @throws PgpSignatureGeneratorException
     */
    void init(File secretKeyring, String keyId, String passphrase) throws FileNotFoundException, IOException, PgpSignatureGeneratorException;
    void signFile(File fileToSign, File outputFile, boolean armor) throws FileNotFoundException, IOException, PgpSignatureGeneratorException;
}
