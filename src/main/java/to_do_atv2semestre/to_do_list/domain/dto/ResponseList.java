package to_do_atv2semestre.to_do_list.domain.dto;

import lombok.Getter;
import lombok.Setter;
import to_do_atv2semestre.to_do_list.domain.Task;
import to_do_atv2semestre.to_do_list.domain.enums.Status;

import java.time.LocalDate;
import java.util.List;
import java.util.stream.Collectors;

@Setter
@Getter
public class ResponseList {
    private List<Task> atrasadas;
    private List<Task> a_fazer;
    private List<Task> em_progresso;
    private List<Task> concluido;

    public ResponseList(List<Task> list) {
        this.atrasadas = list.stream().filter(task -> !task.getStatus().equals(Status.Concluido) && task.getDue_date().isBefore(LocalDate.now())).collect(Collectors.toList());
        this.a_fazer = list.stream().filter(task -> task.getStatus().equals(Status.A_Fazer)).collect(Collectors.toList());
        this.em_progresso = list.stream().filter(task -> task.getStatus().equals(Status.Em_Progresso)).collect(Collectors.toList());
        this.concluido = list.stream().filter(task -> task.getStatus().equals(Status.Concluido)).collect(Collectors.toList());
    }
}
