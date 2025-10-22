package com.bsep.pki.events;

import com.bsep.pki.models.User;
import org.springframework.context.ApplicationEvent;

public class OnPasswordResetRequestEvent extends ApplicationEvent {

    private final User user;

    public OnPasswordResetRequestEvent(User user) {
        super(user);
        this.user = user;
    }

    public User getUser() {
        return user;
    }
}