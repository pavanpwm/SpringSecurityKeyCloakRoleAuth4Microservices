package sec.eci.poc;

import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

@Configuration
@EnableWebSecurity
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

	// configureGlobal() tasks the SimpleAuthorityMapper to make sure roles are not
	// prefixed with ROLE_.
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
		keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
		auth.authenticationProvider(keycloakAuthenticationProvider);
	}

	// keycloakConfigResolver defines that we want to use the Spring Boot properties
	// file support instead of the default keycloak.json.
	@Bean
	public KeycloakSpringBootConfigResolver KeycloakConfigResolver() {
		return new KeycloakSpringBootConfigResolver();
	}

	@Bean
	@Override
	protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
		return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		super.configure(http);
		http.cors().and().authorizeRequests()
			.antMatchers("/modApi1").hasRole("moderator")			
			.antMatchers("/userApi1").hasRole("user")
			.antMatchers("/anon").hasRole("user").
			anyRequest().permitAll();
	}
	
//we can have method level security by adding this annotation in security config class
//	@EnableGlobalMethodSecurity(
//			  prePostEnabled = true, 
//			  securedEnabled = true, 
//			  jsr250Enabled = true)
//then use  @PreAuthorize("hasRole('moderator')") above controller methods
//note that for key cloak the string for role should exactly match the role defined in keycloak
//by default spring security needs roles capitalized and ROLE_ prefix @PreAuthorize("hasRole('ROLE_ADMIN')")
//but in our case we only need to use "admin" i.e the string that we gave for our role in key cloak
//you can name ROLE_ADMIN in keycloak though
	
	
	
// dont forget to change allowed origins in WebConfig.java class
	
	
	/**
	 * 
	 *			First download and run nimbus oj windows
	 *			there is no exe so create a cmd bat and run it
	 *			setup a new realm, users, realm roles, clients(apis)
	 *			get config for those clients and add them to your properties file in spring boot
	 *
	 * 
	 *  		//////////////////
	 * 
	 *
	 * 			For ROLE based authorization Open your keycloak admin dashboard Go to Clients
	 * 			and click on the client you want to map your realm role to it Go to Mappers
	 * 			tab and create a new mapper Under Mapper Type choose User Realm Role And
	 * 			under Token Claim Name type resource_access.${client_id}.roles
	 * 
	 * 
	 * 			////////////
	 * 
	 * 
	 * 			For CORS support -Create a config class
	 * 
	 * 			@Configuration 
	 * 			public class WebConfig implements WebMvcConfigurer {
	 * 				@Override 
	 * 				public void addCorsMappings(CorsRegistry registry) {
	 *           		registry.addMapping("/**").allowedOrigins("*"); 
	 *           	} 
	 *			}
	 * 
	 *           -then configure https.cors().and()... in Spring Security or
	 *           KeycloakSecurity config class
	 * 
	 *           -keycloak.bearer-only=true 
	 *           add this property in application.props file so that when 
	 *           we send auth token with ajax, keycloak can get it
	 * 
	 *           Bearer-only access type means that the application only allows
	 *           bearer token requests. If this is turned on, this application
	 *           cannot participate in browser logins. So if you select your client
	 *           as bearer-only then in that case keycloak adapter will not attempt
	 *           to authenticate users, but only verify bearer tokens.
	 * 
	 *           Before looking at the CORS stuff let's check how you have set up
	 *           your keycloak configuration ? The example you refer to is : a
	 *           SpringBoot REST service and a JS frontend, which means : 
  				 Your REST service must be a particular keyloak client with
	 *           bearer-only. Your frontend service must be a particular
	 *           keycloak client, and your JS app should use the keycloak.js
	 *           adapter. From that client you will be > redirected to the keycloak
	 *           login page, after it redirects back you have to pass the token in
	 *           the header before doing your backend call.  Regarding cors
	 *           config in the properties file, these are not relevant for the
	 *           SpringBoot adapter (we need to document that or make it work ;) )
	 *           but configuring CORS directly in SB should be enough.
	 * 
	 * 
	 * 
	 * 
	 *           -In the front end 
	 *           
	 *           $.ajax({ 
	 *           	type: "GET", 								// [or GET or PUT or DELETE] 
	 *          	url: "http://localhost:8080/modApi1", 
	 *           	dataType: "json", 							    //data type of what are receiving from server 
	 *           	headers : {
	 *           		'Authorization': 'Bearer ' + access_token  // dont forget the space after Bearer 
	 *           	}, 
	 *           	success: function(reponse){
	 *           				document.getElementById("response").innerHTML = JSON.parse(response); 
	 *           			}, 
	 *           	error: function(xhr){ 
	 *           				document.getElementById("response").innerHTML = xhr.responseText;
	 *           		 	} 
	 *           	});
	 * 
	 * 
	 * 
	 *           /////////////
	 * 
	 *           To get user info from tokens, call this method from controller
	 *           method
	 * 
	 *           AccessToken loadUserDetail(KeycloakAuthenticationToken authentication) { 
	 *           	SimpleKeycloakAccount account = (SimpleKeycloakAccount) authentication.getDetails(); 
	 *           	AccessToken token = account.getKeycloakSecurityContext().getToken();
	 *           	System.out.println(token.getRealmAccess().getRoles().toString());
	 *           	return token; 
	 *           }
	 * 
	 * 
	 *           ////////////
	 * 
	 * 
	 * 
	 */

}
