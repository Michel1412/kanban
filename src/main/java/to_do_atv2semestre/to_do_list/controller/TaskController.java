package to_do_atv2semestre.to_do_list.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import to_do_atv2semestre.to_do_list.domain.Task;
import to_do_atv2semestre.to_do_list.domain.dto.CreateTaskDTO;
import to_do_atv2semestre.to_do_list.domain.dto.ListParamQuery;
import to_do_atv2semestre.to_do_list.domain.dto.ResponseList;
import to_do_atv2semestre.to_do_list.domain.dto.UpdateTaskDTO;
import to_do_atv2semestre.to_do_list.service.TaskService;

import java.util.List;

@RestController
@RequestMapping("/tasks")
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TaskController {

    private final TaskService service;

    @GetMapping
    public ResponseEntity<ResponseList> getTask() {
        return ResponseEntity.ok(this.service.listAll());
    }

    @PostMapping
    public ResponseEntity<?> createTask(@RequestBody CreateTaskDTO dto) {
        return this.service.create(dto);
    }

    @PutMapping("/{id}/move")
    public ResponseEntity<?> moveTask(@PathVariable int id) {
        return this.service.move(id);
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> updateDetails(@PathVariable int id, @RequestBody UpdateTaskDTO dto) {
        return this.service.update(id, dto);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteTask(@PathVariable int id) {
        return this.service.delete(id);
    }

}
