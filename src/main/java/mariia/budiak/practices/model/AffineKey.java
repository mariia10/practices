package mariia.budiak.practices.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.util.Arrays;
import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AffineKey {

    @ApiModelProperty(example = "7")
    private Integer alpha;
    @ApiModelProperty(example = "14")
    private Integer beta;

    @JsonIgnore
    private Integer minusAlpha;



}
