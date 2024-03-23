package mariia.budiak.practices.model;

import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.util.HashMap;

@Data
public class AffineRecurrentKeys {
    @ApiModelProperty(example = "{1:{alpha: 7, beta: 14}, 2:{alpha: 5, beta: 13}}")
    private final HashMap<Integer, AffineKey> affineKeyHashMap = new HashMap<>();
}
