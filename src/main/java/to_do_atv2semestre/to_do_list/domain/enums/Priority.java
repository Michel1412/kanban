package to_do_atv2semestre.to_do_list.domain.enums;

public enum Priority {
    baixa(3),
    media(2),
    alta(1);

    private int value;

    Priority(int i) {
        this.value = i;
    }
}
