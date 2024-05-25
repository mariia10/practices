package mariia.budiak.practices.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

import java.security.KeyPair;

@Data
public class GOST34102012 {
    private String publicKey;
    private String privateKey;
    @JsonIgnore
    private KeyPair keyPair;
}
