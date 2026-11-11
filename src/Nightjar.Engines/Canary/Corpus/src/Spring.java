// Canary: Spring request parameter concatenated into SQL (must be found by the taint rules).
@RestController
class UserController {
    @GetMapping("/user")
    String find(@RequestParam String name) {
        return jdbc.queryForObject("SELECT * FROM users WHERE name='" + name + "'", String.class);
    }
}
