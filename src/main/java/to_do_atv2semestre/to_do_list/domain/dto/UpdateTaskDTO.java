package to_do_atv2semestre.to_do_list.domain.dto;

import lombok.Getter;
import to_do_atv2semestre.to_do_list.domain.enums.Priority;

import java.time.LocalDate;

@Getter
public class UpdateTaskDTO {

    private String title;
    private String description;
    private LocalDate dueDate;
    private Priority priority;
}
