package com.mattbertolini.antpgp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.types.LogLevel;
import org.apache.tools.ant.types.Resource;
import org.apache.tools.ant.types.ResourceCollection;
import org.apache.tools.ant.types.resources.FileResource;
import org.apache.tools.ant.types.resources.Union;

import com.mattbertolini.antpgp.bouncycastle.BouncyCastlePgpSignatureGenerator;

/**
 * Ant task for creating signatures using PGP
 * 
 * @author Matt Bertolini
 */
public class PgpSignTask extends Task {
    private static final String FILE_SEPARATOR = System.getProperty("file.separator");

    private PgpSignatureGenerator sigGenerator;
    private File secretKeyring;
    private String keyId;
    private String passphrase;
    private boolean armor;
    private File outputDir;
    private Union files;
    private boolean verbose;

    @Override
    public void init() throws BuildException {
        this.sigGenerator = new BouncyCastlePgpSignatureGenerator();
        this.files = new Union();
        this.armor = true;
        this.verbose = false;
    }

    @Override
    public void execute() throws BuildException {
        if (this.secretKeyring == null) {
            throw new BuildException("Secret keyring is null.");
        } else if (this.keyId == null || this.keyId.isEmpty()) {
            throw new BuildException("Key ID is null or empty.");
        } else if (this.passphrase == null || this.passphrase.isEmpty()) {
            throw new BuildException("Passphrase is null or empty.");
        }
        
        try {
            this.sigGenerator.init(this.secretKeyring, this.keyId, this.passphrase);
        } catch (FileNotFoundException e) {
            throw new BuildException("Secret keyring file not found.", e);
        } catch (IOException e) {
            throw new BuildException("Could not parse secret keyring file.", e);
        } catch (PgpSignatureGeneratorException e) {
            throw new BuildException("Unable to get secret key from keyring.", e);
        }

        Resource[] fileResources = this.files.listResources();
        this.log("Signing " + fileResources.length + " file(s).", LogLevel.INFO.getLevel());
        for (Resource resource : fileResources) {
            if (!(resource instanceof FileResource)) {
                throw new BuildException(resource.getName() + " is not a file.");
            }
            FileResource fileResource = (FileResource) resource;
            File fileToSign = fileResource.getFile();
            String filePath = fileToSign.getAbsolutePath();
            if (!fileToSign.exists()) {
                throw new BuildException(filePath + " not found.");
            }
            
            String outputPath = filePath;
            if(this.outputDir != null) {
                if(!this.outputDir.isDirectory()) {
                    throw new BuildException(this.outputDir + " is not a directory.");
                }
                if(!this.outputDir.exists()) {
                    this.outputDir.mkdir();
                }
                outputPath = this.outputDir.getAbsolutePath() + FILE_SEPARATOR + fileToSign.getName();
                this.log("Saving signed files to " + outputPath, 
                        this.verbose ? LogLevel.INFO.getLevel() : LogLevel.VERBOSE.getLevel());
            }
            File outputFile = null;
            if(this.armor) {
                outputFile = new File(outputPath + ".asc");
            } else {
                outputFile = new File(outputPath + ".sig");
            }
            this.log("Signing " + filePath, this.verbose ? LogLevel.INFO.getLevel() : LogLevel.VERBOSE.getLevel());
            
            try {
                this.sigGenerator.signFile(fileToSign, outputFile, this.armor);
            } catch (FileNotFoundException e) {
                throw new BuildException("Unable to load file " + filePath, e);
            } catch (IOException e) {
                throw new BuildException("Unable to parse files.", e);
            } catch (PgpSignatureGeneratorException e) {
                throw new BuildException("Unable to sign file.", e);
            }
        }
    }

    /**
     * Required. The secret keyring file to use for creating signatures.
     * 
     * @param secretKeyring
     * @since 1.0.0
     */
    public void setSecretKeyring(File secretKeyring) {
        this.secretKeyring = secretKeyring;
    }

    /**
     * Required. The PGP key ID.
     * 
     * @param keyId
     * @since 1.0.0
     */
    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    /**
     * Required. The passphrase associated with the key ID.
     * 
     * @param passphrase
     * @since 1.0.0
     */
    public void setPassphrase(String passphrase) {
        this.passphrase = passphrase;
    }

    /**
     * Optional. Create ASCII armored output. Default is true.
     * 
     * @param armor
     * @since 1.0.0
     */
    public void setArmor(boolean armor) {
        this.armor = armor;
    }
    
    /**
     * Optional. Changes the directory where the signature files will be saved. 
     * Defaults to the same directory as the files being signed.
     * 
     * @param outputDir
     * @since 1.0.0
     */
    public void setOutputDir(File outputDir) {
        this.outputDir = outputDir;
    }
    
    /**
     * Optional. When set to true, enables verbose logging for the task.
     * 
     * @param verbose
     * @since 1.0.0
     */
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public void add(ResourceCollection rc) {
        this.files.add(rc);
    }
}
