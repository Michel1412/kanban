package to_do_atv2semestre.to_do_list.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import to_do_atv2semestre.to_do_list.domain.Task;
import to_do_atv2semestre.to_do_list.domain.enums.Priority;

import java.time.LocalDate;
import java.util.List;

public interface TaskRepository extends JpaRepository<Task, Integer> {

    @Query(value = "SELECT t, " +
            " DENSE_RANK() OVER (ORDER BY t.priority DESC) AS rank " +
            " FROM Task t " +
            " GROUP BY t.status, t.id " +
            " ORDER BY rank, t.due_date ASC ")
    List<Task> findAllOrdered();

    @Query(value = "SELECT t, " +
            " DENSE_RANK() OVER (ORDER BY t.priority DESC) AS rank " +
            " FROM Task t " +
            " WHERE t.priority = :priority AND t.due_date = :due_date " +
            " GROUP BY t.status, t.id " +
            " ORDER BY rank ")
    List<Task> listByPriorityAndByDueDate(@Param("priority") Priority priority,
                                          @Param("due_date") LocalDate dueDate);

    @Query(value = "SELECT t, " +
            " DENSE_RANK() OVER (ORDER BY t.priority DESC) AS rank " +
            " FROM Task t " +
            " WHERE t.priority = :priority " +
            " GROUP BY t.status, t.id " +
            " ORDER BY rank ")
    List<Task> listByPriority(@Param("priority") Priority priority);

    @Query(value = "SELECT t, " +
            " DENSE_RANK() OVER (ORDER BY t.priority DESC) AS rank " +
            " FROM Task t " +
            " WHERE t.due_date = :due_date " +
            " GROUP BY t.status, t.id " +
            " ORDER BY rank ")
    List<Task> listByDueDate(@Param("due_date") LocalDate dueDate);

}
