import java.util.List;
      /* Simple container so we can add more detail later */
public final class ValidationResult {
    private final boolean ok;
    private final List<String> messages;

    ValidationResult(boolean ok, List<String> messages){ 
        this.ok = ok; 
        this.messages = messages; 
    }

    boolean ok(){
        return ok;
    }

    List<String> messages(){
        return messages;
    }
}