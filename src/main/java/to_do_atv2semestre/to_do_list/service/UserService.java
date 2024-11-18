package to_do_atv2semestre.to_do_list.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import to_do_atv2semestre.to_do_list.domain.User;
import to_do_atv2semestre.to_do_list.domain.dto.LoginUserDTO;
import to_do_atv2semestre.to_do_list.domain.dto.RecoveryJwtTokenDTO;
import to_do_atv2semestre.to_do_list.repository.UserRepository;
import to_do_atv2semestre.to_do_list.security.authentication.JwtTokenService;
import to_do_atv2semestre.to_do_list.security.config.SecurityConfiguration;
import to_do_atv2semestre.to_do_list.security.userDetails.UserDetailsImpl;

@Service
public class UserService {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenService jwtTokenService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecurityConfiguration securityConfiguration;

    // Método responsável por autenticar um usuário e retornar um token JWT
    public RecoveryJwtTokenDTO authenticateUser(LoginUserDTO loginUserDto) {
        // Cria um objeto de autenticação com o email e a senha do usuário
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(loginUserDto.getUsername(), loginUserDto.getPassword());

        // Autentica o usuário com as credenciais fornecidas
        Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);

        // Obtém o objeto UserDetails do usuário autenticado
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

        // Gera um token JWT para o usuário autenticado
        return new RecoveryJwtTokenDTO(jwtTokenService.generateToken(userDetails));
    }

    // Método responsável por criar um usuário
    public void createUser(LoginUserDTO dto) {

        // Cria um novo usuário com os dados fornecidos
        User newUser = User.builder()
                .username(dto.getUsername())
                // Codifica a senha do usuário com o algoritmo bcrypt
                .password(securityConfiguration.passwordEncoder().encode(dto.getPassword()))
                .build();

        // Salva o novo usuário no banco de dados
        userRepository.save(newUser);
    }

    public ResponseEntity<RecoveryJwtTokenDTO> login(LoginUserDTO dto) {
        var optUser = this.userRepository.findByUsername(dto.getUsername());

        if (optUser.isEmpty()) {
            this.createUser(dto);
        }

        var token = this.authenticateUser(dto);
        return ResponseEntity.ok(token);
    }
}
