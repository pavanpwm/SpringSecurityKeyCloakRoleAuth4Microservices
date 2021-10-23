package sec.eci.poc;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;



@RestController
public class POCController {


	@GetMapping(path = "/modApi1")
	public String mod(KeycloakAuthenticationToken authentication) {
        return "yes you are mod of api 1";
	}
	    
	@GetMapping(path = "/userApi1")
	public String users(KeycloakAuthenticationToken authentication) {
	    return  "yes you are user of api 1";
	}
	
	@GetMapping(path = "/anon")
	public String anon() {
		return "Hello World";
	}
	
	@GetMapping(path = "/logout")
	public String logout(HttpServletRequest req) throws ServletException {
		req.logout();
	    return  "Logged out using api 1";
	}
	
		
	
}
