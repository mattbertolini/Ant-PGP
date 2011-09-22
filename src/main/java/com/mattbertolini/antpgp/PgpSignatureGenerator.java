package com.mattbertolini.antpgp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * 
 * @author Matt Bertolini
 */
public interface PgpSignatureGenerator {
    void init(File secretKeyring, String keyId, String passphrase) throws FileNotFoundException, IOException, PgpSignatureGeneratorException;
    void signFile(File fileToSign, File outputFile, boolean armor) throws FileNotFoundException, IOException, PgpSignatureGeneratorException;
}
