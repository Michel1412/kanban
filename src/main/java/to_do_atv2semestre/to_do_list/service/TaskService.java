package to_do_atv2semestre.to_do_list.service;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.ResponseBody;
import to_do_atv2semestre.to_do_list.domain.Task;
import to_do_atv2semestre.to_do_list.domain.dto.CreateTaskDTO;
import to_do_atv2semestre.to_do_list.domain.dto.ResponseList;
import to_do_atv2semestre.to_do_list.domain.dto.UpdateTaskDTO;
import to_do_atv2semestre.to_do_list.repository.TaskRepository;

import java.util.Objects;

@Service
@RequiredArgsConstructor
public class TaskService {

    private final TaskRepository taskRepository;

    public ResponseList listAll() {
        return new ResponseList(this.taskRepository.findAllOrdered());
    }

    public ResponseEntity<?> create(CreateTaskDTO dto) {
        if (Objects.isNull(dto) || dto.getTitle().isEmpty()) {
            return new ResponseEntity<>("Erro: Não é permitido salvar uma Tarefa sem Title", HttpStatus.BAD_REQUEST);
        }

        Task task = new Task(dto);

        return ResponseEntity.ok(this.taskRepository.save(task));
    }

    public ResponseEntity<?> move(int id) {
        var optTask = this.taskRepository.findById(id);

        if (optTask.isEmpty()) {
            return new ResponseEntity<>(String.format("Não foi encontrado uma Task com id: %d", id), HttpStatus.BAD_REQUEST);
        }

        Task task = optTask.get().moveToNextStatus();

        return ResponseEntity.ok(this.taskRepository.save(task));
    }


    public ResponseEntity<?> update(int id, UpdateTaskDTO dto) {
        var optTask = this.taskRepository.findById(id);

        if (optTask.isEmpty()) {
            return new ResponseEntity<>(String.format("Não foi encontrado uma Task com id: %d", id), HttpStatus.BAD_REQUEST);
        }

        Task task = optTask.get().update(dto);

        return ResponseEntity.ok(this.taskRepository.save(task));
    }

    public ResponseEntity<String> delete(int id) {
        var optTask = this.taskRepository.findById(id);

        if (optTask.isEmpty()) {
            throw new RuntimeException(String.format("Não foi encontrado uma Task com id: %d", id));
        }

        this.taskRepository.deleteById(id);
        return ResponseEntity.ok(String.format("Task: %d deletada com Sucesso!", id));
    }

}
