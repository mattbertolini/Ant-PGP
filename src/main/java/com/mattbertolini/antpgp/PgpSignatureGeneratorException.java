package com.mattbertolini.antpgp;

public class PgpSignatureGeneratorException extends Exception {
    private static final long serialVersionUID = -2414903246805029175L;

    public PgpSignatureGeneratorException() {
        super();
    }

    public PgpSignatureGeneratorException(String message, Throwable cause) {
        super(message, cause);
    }

    public PgpSignatureGeneratorException(String message) {
        super(message);
    }

    public PgpSignatureGeneratorException(Throwable cause) {
        super(cause);
    }
}
