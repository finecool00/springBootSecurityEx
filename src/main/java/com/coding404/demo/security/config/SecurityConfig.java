package com.coding404.demo.security.config;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.coding404.demo.user.MyUserDetailService;

@Configuration //설정파일임을 정의함
@EnableWebSecurity //이 설정파일을 시큐리티 필터에 추가
@EnableGlobalMethodSecurity(prePostEnabled = true) //어노테이션으로 권한을 지정할 수 있게 함
public class SecurityConfig {
	
	//나를기억해에서 사용할 UserDetailService
	@Autowired
	private MyUserDetailService myUserDetailService;
	
	
	
	//비밀번호 암호화객체
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	
	
	@Bean
	public SecurityFilterChain securityfilter(HttpSecurity http) throws Exception {
		
		//csrf토큰 X
		http.csrf().disable();
		
		//권한설정
		//시큐리티는 빌더패턴이 기본!.찍어서 연결 작성
		//http.authorizeHttpRequests( authorize -> authorize.anyRequest().permitAll());
		
		//모든페이지에 대해 거부
		//http.authorizeHttpRequests( authorize -> authorize.anyRequest().denyAll());
		
		//user페이지에 대한 인증이 필요(anMatchers)
		//http.authorizeHttpRequests( authorize -> authorize.
		//										 antMatchers("/user/**").authenticated());
		
		
		//user페이지에 대해서 권한이 필요 -> 권한이 없으면 forbidden이라고 뜸
//		http.authorizeHttpRequests(authorize -> authorize.antMatchers("/user/**").hasRole("USER")); //로그인하면 로그인을 시도했던 페이지로 보냄(이동)
		
		
		//user페이지는 user권한이 필요, admin페이지는 admin권한이 필요
//		http.authorizeHttpRequests(authorize -> authorize.antMatchers("/user/**").hasRole("USER")
//														 .antMatchers("/admin/**").hasRole("ADMIN")       );
		
		
		//의미 : all페이지는 인증만 되면 됨, user페이지는 user권한, admin페이지는 admin권한, 나머지 모든 페이지는 접근 가능
		//http.authorizeHttpRequests(authorize -> authorize.antMatchers("/all").authenticated() //all페이지는 인증된 사람만
														 //.antMatchers("/user/**").hasRole("USER") //user페이지는 user권한 있는 사람만
														 //.antMatchers("/admin/**").hasRole("ADMIN") //admin페이지는 admin권한 있는 사람만
														 //.anyRequest().permitAll()); //그 외 모든 요청은 허용
		
		//all페이지는 인증만 되면 됨, user페이지는 3중 1개의 권한을 가지면 됨....! 등등
		//권한 앞에는 ROLE_ 가 자동으로 생성됨!!(중요!!)
		http.authorizeHttpRequests(authorize -> authorize.antMatchers("/all").authenticated()
				 .antMatchers("/user/**").hasAnyRole("USER", "ADMIN", "TESTER")
				 .antMatchers("/admin/**").hasRole("ADMIN")
				 .anyRequest().permitAll()); //그 외 모든 요청은 허용
		
		//시큐리티 설정파일 만들면, 시큐리티가 제공하는 기본 로그인페이지가 보이지 않게 됩니다.
		//시큐리티가 사용하는 기본로그인페이지를 사용함
		//권한 or 인증이 되지 않으면 기본으로 선언된 로그인페이지를 보여주게 됩니다.
		//http.formLogin(Customizer.withDefaults()); //기본로그인페이지 사용(인증이 필요한 페이지에 대해서)
		
		//사용자가 제공하는 폼기반 로그인기능을 사용할 수 있습니다.
		http.formLogin().loginPage("/login") //로그인페이지 요청경로는 반드시 지켜줘야함...
					    .loginProcessingUrl("/loginForm") //로그인시도 요청경로 -> 스프링이 로그인 시도를 낚아채서 UserDetailService객체로 연결
						.defaultSuccessUrl("/all")//로그인 성공 시 이동 경로
						.failureUrl("/login?err=true") //로그인 실패시 이동할 url
						.and()
						.exceptionHandling().accessDeniedPage("/deny") //권한이 없을 때 이동할 리다이렉트 경로
						.and()
						.logout().logoutUrl("/logout").logoutSuccessUrl("/hello"); //default로그아웃 경로는 /logout, 로그아웃 주소를 직접 작성할 수 있고, 로그아웃 성공 시 리다이렉트할 경로 지정 가능
					    //usernameParameter("id") ... username이 아닌 다른 파라미터 이름으로 바꿀 수 있음(참고만 할 것!!!)
		
		//나를 기억해..
		http.rememberMe()
			.key("coding404") //토큰(쿠키)을 만들어 비밀키로! (필수)
			.rememberMeParameter("remember-me") //화면에서 전달받는 checked name명입니다 (필수)
			.tokenValiditySeconds(60) //쿠키(토큰)의 유효시간 (필수)
			.userDetailsService(myUserDetailService) // 토큰이 있을 때 실행시킬 UserDetailService 객체
			.authenticationSuccessHandler(customRememberMe()); //나를 기억해가 동작할 때, 실행할 핸들러객체를 호출!?!
		return http.build();
	}
	
	//customRememberMe
	@Bean
	public CustomRememberMe customRememberMe() {
		CustomRememberMe me = new CustomRememberMe("/all"); //리멤버에 성공시 실행시킬 리다이렉트 주소
		return me;
	}

	
	
}
