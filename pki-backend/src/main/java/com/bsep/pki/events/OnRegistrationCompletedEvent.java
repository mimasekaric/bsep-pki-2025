package com.bsep.pki.events;

import com.bsep.pki.models.User;
import org.springframework.context.ApplicationEvent;

public class OnRegistrationCompletedEvent extends ApplicationEvent {
    private final User user;

    public OnRegistrationCompletedEvent(User user) {
        super(user);
        this.user = user;
    }

    public User getUser() {
        return user;
    }
}
