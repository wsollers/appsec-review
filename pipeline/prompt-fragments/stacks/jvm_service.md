---
id: jvm_service
version: 1
covers: []
standards: ["cwe", "asvs5", "api-top10-2023"]
max_tokens: 1500
---
## Runtime and framework model
A Java or Kotlin service on the JVM: Spring Boot (MVC or WebFlux), Jakarta EE/Servlet containers,
Micronaut, Quarkus, Ktor, Dropwizard, or Vert.x. Dependency injection wires controllers,
filters, and repositories; much behaviour comes from annotations and auto-configuration rather
than visible calls. Memory safety is provided by the runtime except at JNI and `Unsafe` boundaries.

## Trust and interface layer
- Entry points: `@RestController`/`@Controller` methods with `@RequestMapping` variants, JAX-RS
  `@Path` resources, servlets, `@KafkaListener`/`@RabbitListener`/`@JmsListener` consumers,
  `@Scheduled` jobs reading external data, gRPC-java services.
- Data binding converts parameters, JSON (Jackson), and form fields into objects automatically,
  including nested properties.
- Spring Security's `SecurityFilterChain` (or legacy `WebSecurityConfigurerAdapter`) decides which
  paths are authenticated; method security (`@PreAuthorize`, `@Secured`) decides per method when
  `@EnableMethodSecurity` is present.

## Idiomatic security mechanisms
- `requestMatchers(...).authenticated()` with `anyRequest().denyAll()` or `authenticated()` last;
  CSRF enabled for cookie sessions.
- JPA/JDBC parameter binding (`?`, `:name`, Criteria API, Spring Data derived queries).
- Jackson without default typing; `ObjectInputFilter` for any Java serialization.
- Bean Validation (`@Valid`, `@Size`, `@Pattern`) on DTOs; DTOs separate from entities.
- Thymeleaf/JSP JSTL escaping (`th:text`, `<c:out>`).
- `XMLConstants.FEATURE_SECURE_PROCESSING` and disabled DTDs on every XML factory.

## Stack-specific pitfalls
- Matcher ordering: `permitAll()` patterns listed before restrictive ones; `mvcMatchers` vs
  `antMatchers` path-normalization differences (`/admin/` vs `/admin`, `;jsessionid`).
- Spring Data REST or Actuator exposing repositories and endpoints (`/actuator/env`,
  `/actuator/heapdump`) via `management.endpoints.web.exposure.include=*`.
- SpEL evaluated on request data (`@Value` misuse, `ExpressionParser.parseExpression(input)`),
  Log4j lookups in vulnerable versions.
- `@ModelAttribute` binding to JPA entities (mass assignment), `@RequestBody` into entities.
- Native queries built with string concatenation inside `@Query(nativeQuery = true)` or
  `EntityManager.createNativeQuery`.
- `RestTemplate`/`WebClient` fetching user URLs (SSRF).
- `ObjectInputStream` in RMI, JMX, session replication, or caches.

## Build and deployment facts to check
- Spring profiles active in deployment and per-profile properties (`application-prod.yml`).
- Actuator exposure, management port, and whether it is network reachable.
- Dependency versions from the resolved Maven/Gradle graph (Log4j, Jackson-databind, Spring,
  SnakeYAML, commons-collections gadgets present on the classpath).
- JVM flags enabling remote debug (`-agentlib:jdwp`) or JMX without authentication.
- Container base image and the user the JVM runs as.
