package to_do_atv2semestre.to_do_list.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import to_do_atv2semestre.to_do_list.domain.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
