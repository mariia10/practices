package mariia.budiak.practices.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.annotations.ApiModelProperty;
import lombok.Data;

import java.util.*;

@Data
public class SubKey {
    @JsonIgnore
    private List<Character> alphabet =
            Arrays.asList(
                    'a', 'b', 'c', 'd', 'e', 'f', 'g',
                    'h', 'i', 'j', 'k', 'l', 'm', 'n',
                    'o', 'p', 'q', 'r', 's', 't', 'u',
                    'v', 'w', 'x', 'y', 'z');

    ///A a B b C c D d E e F f G g H h I i J j K k L l M m N n O o P p Q q R r S s T t U u V v W w X x Y y Z z
    @ApiModelProperty(example = "f")
    private String a;
    @ApiModelProperty(example = "x")
    private String b;
    @ApiModelProperty(example = "w")
    private String c;
    @ApiModelProperty(example = "p")
    private String d;
    @ApiModelProperty(example = "t")
    private String e;
    @ApiModelProperty(example = "q")
    private String f;
    @ApiModelProperty(example = "l")
    private String g;
    @ApiModelProperty(example = "u")
    private String h;
    @ApiModelProperty(example = "s")
    private String i;
    @ApiModelProperty(example = "j")
    private String j;
    @ApiModelProperty(example = "b")
    private String k;
    @ApiModelProperty(example = "v")
    private String l;
    @ApiModelProperty(example = "r")
    private String m;
    @ApiModelProperty(example = "e")
    private String n;
    @ApiModelProperty(example = "m")
    private String o;
    @ApiModelProperty(example = "h")
    private String p;
    @ApiModelProperty(example = "z")
    private String q;
    @ApiModelProperty(example = "n")
    private String r;
    @ApiModelProperty(example = "g")
    private String s;
    @ApiModelProperty(example = "o")
    private String t;
    @ApiModelProperty(example = "k")
    private String u;
    @ApiModelProperty(example = "c")
    private String v;
    @ApiModelProperty(example = "i")
    private String w;
    @ApiModelProperty(example = "a")
    private String x;
    @ApiModelProperty(example = "y")
    private String y;
    @ApiModelProperty(example = "d")
    private String z;


    public SubKey() {
        shuffle();
        this.a = String.valueOf(alphabet.get(0));
        this.b = String.valueOf(alphabet.get(1));
        this.c = String.valueOf(alphabet.get(2));
        this.d = String.valueOf(alphabet.get(3));
        this.e = String.valueOf(alphabet.get(4));
        this.f = String.valueOf(alphabet.get(5));
        this.g=String.valueOf(alphabet.get(6));
        this.h=String.valueOf(alphabet.get(7));
        this.i=String.valueOf(alphabet.get(8));
        this.j=String.valueOf(alphabet.get(9));
        this.k=String.valueOf(alphabet.get(10));
        this.l=String.valueOf(alphabet.get(11));
        this.m=String.valueOf(alphabet.get(12));
        this.n=String.valueOf(alphabet.get(13));
        this.o=String.valueOf(alphabet.get(14));
        this.p=String.valueOf(alphabet.get(15));
        this.q=String.valueOf(alphabet.get(16));
        this.r=String.valueOf(alphabet.get(17));
        this.s=String.valueOf(alphabet.get(18));
        this.t=String.valueOf(alphabet.get(19));
        this.u=String.valueOf(alphabet.get(20));
        this.v=String.valueOf(alphabet.get(21));
        this.w=String.valueOf(alphabet.get(22));
        this.x=String.valueOf(alphabet.get(23));
        this.y=String.valueOf(alphabet.get(24));
        this.z=String.valueOf(alphabet.get(25));


    }

    public void shuffle() {
        Collections.shuffle(alphabet, new Random());
    }

}
