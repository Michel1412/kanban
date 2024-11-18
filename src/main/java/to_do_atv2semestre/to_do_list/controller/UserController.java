package to_do_atv2semestre.to_do_list.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import to_do_atv2semestre.to_do_list.domain.dto.LoginUserDTO;
import to_do_atv2semestre.to_do_list.domain.dto.RecoveryJwtTokenDTO;
import to_do_atv2semestre.to_do_list.service.UserService;

@RestController
@RequestMapping("/auth")
public class UserController {

    @Autowired
    private UserService service;

    @PostMapping("/login")
    public ResponseEntity<RecoveryJwtTokenDTO> authenticateUser(@RequestBody LoginUserDTO dto) {
        return this.service.login(dto);
    }

}