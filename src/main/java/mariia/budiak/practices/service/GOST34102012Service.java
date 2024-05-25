package mariia.budiak.practices.service;

import mariia.budiak.practices.model.GOST34102012;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jcajce.provider.asymmetric.ecgost12.ECGOST2012SignatureSpi512;
import org.bouncycastle.jce.spec.GOST3410ParameterSpec;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;

import java.security.*;
import java.util.Base64;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

import javax.annotation.PostConstruct;

@Service
public class GOST34102012Service {

    private GOST34102012 gost34102012 = new GOST34102012();

    @PostConstruct
    void initKeys(){
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

        //  KeyPair kp = keyPair.generateKeyPair();
        // создание генератора ключевой пары
        // final java.security.KeyPairGenerator keyGen = java.security.KeyPairGenerator.getInstance("GOST3410");

        // генерирование ключевой пары
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
        return sign(gost34102012.getKeyPair().getPrivate(), data);
    }

    private byte[] sign(PrivateKey privateKey,
                        byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, OperatorCreationException, CMSException, IOException {
        CMSProcessableByteArray msg = new CMSProcessableByteArray(data);
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner signer = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("GOST3411WITHECGOST3410-2012-512").setProvider("BC").build(privateKey);
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(signer, new byte[]{}));
        CMSSignedData sigData = gen.generate(msg, false);
        byte[] sign = sigData.getEncoded(); //result here
        return sign;
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


    private boolean verify(PublicKey publicKey,
                           byte[] data, byte[] signature) throws Exception {
        boolean checkResult = false;

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

    /**
     * Проверка подписи на открытом ключе
     *
     * @param data подписываемые данные
     * @param signature подпись
     * @return true - верна, false - не верна
     * @throws Exception /
     */
    public boolean verify(byte[] data, byte[] signature) throws Exception {
        return verify(gost34102012.getKeyPair().getPublic(), data, signature);
    }
}
