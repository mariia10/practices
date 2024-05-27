package mariia.budiak.practices.service;

import lombok.extern.slf4j.Slf4j;
import mariia.budiak.practices.model.GOST34102012;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Service
@Slf4j
public class GOST34102012Service {

    private GOST34102012 gost34102012 = new GOST34102012();

    @PostConstruct
    void initKeys() {
        try {
            this.gost34102012 = genKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * генерирование ключевой пары
     *
     * @return ключевая пара
     * @throws Exception /
     */
    public GOST34102012 genKey()
            throws Exception {
        KeyPairGenerator keypairGen = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
        keypairGen.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA"));
        // генерирование ключевой пары
        log.trace("алгоритм {}", keypairGen.getAlgorithm());
        gost34102012.setKeyPair(keypairGen.generateKeyPair());
        return gost34102012;
    }

    /**
     * Создание подписи
     *
     * @param data подписываемые данные
     * @return подпись
     * @throws Exception /
     */
    public byte[] sign(byte[] data) throws Exception {
        return sign(gost34102012.getUpPrivateKey()==null?
                gost34102012.getKeyPair().getPrivate():
                gost34102012.getUpPrivateKey(), data);
    }

    /**
     * Проверка подписи на открытом ключе
     *
     * @param data      подписываемые данные
     * @param signature подпись
     * @return true - верна, false - не верна
     * @throws Exception /
     */
    public boolean verify(byte[] data, byte[] signature) throws Exception {
        return verify(gost34102012.getUpPublicKey()==null?
                gost34102012.getKeyPair().getPublic():
                gost34102012.getUpPublicKey(), data, signature);
    }

    /**
     * @param file входящий файл для подписи,
     * @return подпись
     */
    public byte[] signFile(MultipartFile file) throws Exception {
        return sign(file.getBytes());
    }

    private byte[] sign(PrivateKey privateKey,
                        byte[] data) throws OperatorCreationException, CMSException, IOException {
        CMSProcessableByteArray msg = new CMSProcessableByteArray(data);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("GOST3411WITHECGOST3410-2012-512").setProvider("BC").build(privateKey);
        gen.addSignerInfoGenerator(new SignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                .build(signer, new byte[]{}));
        CMSSignedData sigData = gen.generate(msg, false);
        return sigData.getEncoded();
    }

    /**
     * @param file входящий файл для подписи,
     * @param sign подпись base 64
     * @return результат верификации подписи
     */
    public boolean verifySignedFile(MultipartFile file, String sign) throws Exception {
        return verify(file.getBytes(),
                Base64.getDecoder().decode(sign));
    }

    /**
     * генерирование ключевой пары
     *
     * @return ключевая пара
     * @throws Exception /
     */
    public GOST34102012 getKey()
            throws Exception {
        KeyPairGenerator keypairGen = KeyPairGenerator.getInstance("ECGOST3410-2012", "BC");
        keypairGen.initialize(new ECGenParameterSpec("Tc26-Gost-3410-12-512-paramSetA"));

        //  KeyPair kp = keyPair.generateKeyPair();
        // создание генератора ключевой пары
        // final java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("GOST3410");

        // генерирование ключевой пары
        return gost34102012;
    }

    /**
     * upload private key
     *
     * @return ключевая пара
     * @throws Exception /
     */
    public String uploadPrivateKey(String privateKey)
            throws Exception {
        byte[] encoded = Base64.getDecoder().decode(privateKey.getBytes());

        KeyFactory keyFactory = KeyFactory.getInstance("ECGOST3410-2012", "BC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        var genPrivateKey = keyFactory.generatePrivate(keySpec);
        gost34102012.setUpPrivateKey(genPrivateKey);
        return Base64.getEncoder().encodeToString(genPrivateKey.getEncoded());
    }

    /**
     * upload private key
     *
     * @return ключевая пара
     * @throws Exception /
     */
    public String uploadPublicKey(String publicKey)
            throws Exception {
        byte[] encoded = Base64.getDecoder().decode(publicKey.getBytes());

        KeyFactory keyFactory = KeyFactory.getInstance("ECGOST3410-2012", "BC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        var publicKeyGen = keyFactory.generatePublic(keySpec);
        gost34102012.setUpPublicKey(publicKeyGen);
        return Base64.getEncoder().encodeToString(publicKeyGen.getEncoded());
    }


    private boolean verify(PublicKey publicKey,
                           byte[] data, byte[] signature) {
        boolean checkResult;

        CMSProcessable signedContent = new CMSProcessableByteArray(data);
        CMSSignedData signedData;
        try {
            signedData = new CMSSignedData(signedContent, signature);
        } catch (CMSException e) {
            return false;
        }

        SignerInformation signer;
        try {
            signer = signedData.getSignerInfos().getSigners().iterator().next();
            checkResult = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(publicKey));

        } catch (Exception ex) {
            return false;
        }
        return checkResult;
    }


}
