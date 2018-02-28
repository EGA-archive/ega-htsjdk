package htsjdk.samtools.seekablestream.cipher;

import com.google.common.util.concurrent.SimpleTimeLimiter;
import com.google.common.util.concurrent.TimeLimiter;
import com.google.common.util.concurrent.UncheckedTimeoutException;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;

public class GPGCipherStream extends InputStream {

    private static final int TIMEOUT = 100;

    private final TimeLimiter timeLimiter;
    private final InputStream seekableInputStream;
    private final OutputStream encryptedOutStream;
    private final OutputStream compressedOutputStream;
    private final OutputStream literalDataOutStream;
    private final PipedInputStream pipedInputStream;
    private final PipedOutputStream pipedOutputStream;

    public GPGCipherStream(InputStream inputStream, PGPPublicKey publicKey) throws IOException, PGPException {
        this(inputStream, publicKey, "");
    }

    public GPGCipherStream(InputStream inputStream, PGPPublicKey publicKey, String filename) throws IOException, PGPException {
        this.timeLimiter = new SimpleTimeLimiter();
        this.seekableInputStream = inputStream;
        BcPGPDataEncryptorBuilder dataEncryptorBuilder = new BcPGPDataEncryptorBuilder(publicKey.getAlgorithm());
        dataEncryptorBuilder.setWithIntegrityPacket(true);
        dataEncryptorBuilder.setSecureRandom(new SecureRandom());
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptorBuilder);
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));
        this.pipedInputStream = new PipedInputStream();
        this.pipedOutputStream = new PipedOutputStream(pipedInputStream);
        this.encryptedOutStream = encryptedDataGenerator.open(pipedOutputStream, new byte[1 << 16]);
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);
        this.compressedOutputStream = compressedDataGenerator.open(encryptedOutStream);
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        this.literalDataOutStream = literalDataGenerator.open(compressedOutputStream, PGPLiteralData.BINARY, String.valueOf(filename), PGPLiteralData.NOW, new byte[1 << 16]);
        new Thread(() -> {
            try {
                IOUtils.copyLarge(seekableInputStream, literalDataOutStream);
            } catch (IOException ignored) {
            }
        }).start();
    }

    @Override
    public int read() throws IOException {
        try {
            return timeLimiter.callWithTimeout(pipedInputStream::read, TIMEOUT, TimeUnit.MILLISECONDS, true);
        } catch (UncheckedTimeoutException e) {
            literalDataOutStream.flush();
            literalDataOutStream.close();
            compressedOutputStream.close();
            encryptedOutStream.close();
            pipedOutputStream.close();
            return -1;
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    public int available() throws IOException {
        return pipedInputStream.available();
    }

    public void close() throws IOException {
        seekableInputStream.close();
    }

}
