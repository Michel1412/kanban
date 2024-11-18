package to_do_atv2semestre.to_do_list.domain.dto;

import lombok.Getter;

@Getter
public class RecoveryJwtTokenDTO {
    private String token;

    public RecoveryJwtTokenDTO(String s) {
        this.token = s;
    }
}
