package htsjdk.samtools.seekablestream.cipher;

import htsjdk.samtools.seekablestream.SeekableStream;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;

public class GPGCipherStream extends InputStream {

    private final SeekableStream inputStream;
    private final ByteArrayOutputStream byteArrayOutputStream;
    private final OutputStream encryptedOutStream;
    private final OutputStream compressedOutputStream;
    private final OutputStream literalDataOutStream;

    public GPGCipherStream(SeekableStream inputStream, PGPPublicKey publicKey) throws IOException, PGPException {
        this(inputStream, publicKey, "");
    }

    public GPGCipherStream(SeekableStream inputStream, PGPPublicKey publicKey, String filename) throws IOException, PGPException {
        this.inputStream = inputStream;
        this.byteArrayOutputStream = new ByteArrayOutputStream();
        BcPGPDataEncryptorBuilder dataEncryptorBuilder = new BcPGPDataEncryptorBuilder(publicKey.getAlgorithm());
        dataEncryptorBuilder.setWithIntegrityPacket(true);
        dataEncryptorBuilder.setSecureRandom(new SecureRandom());
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(dataEncryptorBuilder);
        encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));
        this.encryptedOutStream = encryptedDataGenerator.open(byteArrayOutputStream, new byte[1 << 16]);
        PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(PGPCompressedData.ZLIB);
        this.compressedOutputStream = compressedDataGenerator.open(encryptedOutStream);
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        this.literalDataOutStream = literalDataGenerator.open(compressedOutputStream, PGPLiteralData.BINARY, String.valueOf(filename), PGPLiteralData.NOW, new byte[1 << 16]);
    }

    @Override
    public int read() throws IOException {
        byte[] bytes = new byte[1];
        return read(bytes, 0, 1);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (inputStream.eof()) {
            return -1;
        }
        IOUtils.copyLarge(inputStream, literalDataOutStream, 0, len);
        if (inputStream.eof()) {
            literalDataOutStream.flush();
            literalDataOutStream.close();
            compressedOutputStream.close();
            encryptedOutStream.close();
            byteArrayOutputStream.close();
        }
        byte[] encryptedBytes = byteArrayOutputStream.toByteArray();
        int read = encryptedBytes.length;
        if (read > b.length) {
            throw new IOException("Buffer is too small: should be at least " + read + " bytes!");
        }
        System.arraycopy(encryptedBytes, 0, b, off, read);
        byteArrayOutputStream.reset();
        return read;
    }


}
