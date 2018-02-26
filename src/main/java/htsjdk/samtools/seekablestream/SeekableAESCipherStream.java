package htsjdk.samtools.seekablestream;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class SeekableAESCipherStream extends SeekableStream {

    private SeekableStream encryptedStream;
    private int dataStart;
    private SecretKeySpec secretKeySpec;
    private IvParameterSpec initialIVParameterSpec;
    private Cipher aesCipher;
    private long block;

    public SeekableAESCipherStream(SeekableStream input, byte[] privateKeyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, InvalidKeyException, NoSuchProviderException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        encryptedStream = input;
        encryptedStream.seek(0);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        int headerLength;
        int keyNumber;
        int encryptedSecretSize;
        int nonceSize;
        String aesMode;
        InputStreamReader inputStreamReader = new InputStreamReader(encryptedStream);
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        String header = bufferedReader.readLine();
        headerLength = header.length() + 1; // +1 for linebreak
        String[] parts = header.split("\\|");
        keyNumber = Integer.parseInt(parts[0]);
        encryptedSecretSize = Integer.parseInt(parts[1]);
        nonceSize = Integer.parseInt(parts[2]);
        aesMode = parts[3].replace("b'", "").replace("'", "");

        this.dataStart = headerLength + encryptedSecretSize + nonceSize;

        encryptedStream.seek(0);

        byte[] headerBytes = new byte[headerLength];
        byte[] encryptedSecretBytes = new byte[encryptedSecretSize];
        byte[] nonceBytes = new byte[nonceSize];
        encryptedStream.read(headerBytes, 0, headerLength);
        encryptedStream.read(encryptedSecretBytes, 0, encryptedSecretSize);
        encryptedStream.read(nonceBytes, 0, nonceSize);
        byte[] ivBytes = new byte[16];
        System.arraycopy(nonceBytes, 0, ivBytes, 0, nonceBytes.length);
        System.arraycopy(new byte[8], 0, ivBytes, nonceBytes.length, nonceBytes.length);

        Cipher rsaCipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedSecretBytes = rsaCipher.doFinal(encryptedSecretBytes);

        secretKeySpec = new SecretKeySpec(decryptedSecretBytes, "AES");
        initialIVParameterSpec = new IvParameterSpec(ivBytes);
        aesCipher = Cipher.getInstance("AES/" + aesMode + "/NoPadding", "BC"); // currently only CTR mode is supported
        aesCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, initialIVParameterSpec);
    }

    @Override
    public long length() {
        return encryptedStream.length() - dataStart;
    }

    @Override
    public long position() throws IOException {
        return encryptedStream.position() - dataStart;
    }

    @Override
    public void seek(long position) throws IOException {
        encryptedStream.seek(position + dataStart);

        long newBlock = position / aesCipher.getBlockSize();
        if (newBlock == block) {
            return;
        }

        block = newBlock;

        // Update CTR IV counter according to block number
        BigInteger ivBI = new BigInteger(initialIVParameterSpec.getIV());
        ivBI = ivBI.add(BigInteger.valueOf(block));
        IvParameterSpec newIVParameterSpec = new IvParameterSpec(ivBI.toByteArray());

        try {
            aesCipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
            aesCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, newIVParameterSpec);
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    @Override
    public long skip(long n) throws IOException {
        seek(position() + n);
        return n;
    }

    @Override
    public int read() throws IOException {
        byte[] bytes = new byte[1];
        return read(bytes, 0, 1);
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        int blockSize = aesCipher.getBlockSize();
        long currentPosition = position();
        long startBlock = currentPosition / blockSize;
        long start = startBlock * blockSize;
        long endBlock = (currentPosition + length) / blockSize + 1;
        long end = endBlock * blockSize;
        int prepended = (int) (currentPosition - start);
        int appended = (int) (end - (currentPosition + length));
        encryptedStream.seek(start + dataStart);
        int total = prepended + length + appended;
        byte[] encryptedBytes = new byte[total];
        encryptedStream.read(encryptedBytes, offset, total);
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(encryptedBytes);
        CipherInputStream cipherInputStream = new CipherInputStream(byteArrayInputStream, aesCipher);
        cipherInputStream.read(new byte[prepended]);
        int read = cipherInputStream.read(buffer, offset, length);
        encryptedStream.seek(currentPosition + length + dataStart);
        return read;
    }

    @Override
    public void close() throws IOException {
        encryptedStream.close();
    }

    @Override
    public boolean eof() throws IOException {
        return encryptedStream.eof();
    }

    @Override
    public String getSource() {
        return encryptedStream.getSource();
    }

}