package to_do_atv2semestre.to_do_list.domain.dto;

import lombok.Getter;
import org.antlr.v4.runtime.misc.NotNull;
import to_do_atv2semestre.to_do_list.domain.enums.Priority;

import java.time.LocalDate;

@Getter
public class CreateTaskDTO {

    @NotNull
    private String title;
    private String description;
    private LocalDate dueDate;
    private Priority priority;

}
