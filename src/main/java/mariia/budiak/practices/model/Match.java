package mariia.budiak.practices.model;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class Match {
    private final Character character;
    private final Integer charNumber;
}
