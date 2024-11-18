package to_do_atv2semestre.to_do_list.domain.dto;

import lombok.Getter;
import lombok.Setter;
import to_do_atv2semestre.to_do_list.domain.enums.Priority;

import java.time.LocalDate;

@Setter
@Getter
public class ListParamQuery {
    private Priority priority;
    private LocalDate dueDate;
}
