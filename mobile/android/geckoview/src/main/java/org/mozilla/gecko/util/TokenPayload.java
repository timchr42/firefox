package org.mozilla.gecko.util;

import androidx.annotation.Nullable;

public final class TokenPayload {
    public String cookieName;       // "*" for any name
    public String cookieValue;      // "*" for any value
    public String applicationId;
    public String versionName;
    public String destinationDomain;
    public AccessRights accessRights;
    public boolean globalJar;

    public enum AccessRights {
        NONE,
        READ,
        WRITE,
        READ_WRITE
    }

    public TokenPayload(
            String cookieName,
            String cookieValue,
            String applicationId,
            String versionName,
            String destinationDomain,
            AccessRights accessRights,
            boolean globalJar
    ) {
        this.cookieName = cookieName;
        this.cookieValue = cookieValue;
        this.applicationId = applicationId;
        this.versionName = versionName;
        this.destinationDomain = destinationDomain;
        this.accessRights = accessRights;
        this.globalJar = globalJar;
    }

    public boolean canRead() {
        return accessRights == AccessRights.READ || accessRights == AccessRights.READ_WRITE;
    }

    public boolean canWrite() {
        return accessRights == AccessRights.WRITE || accessRights == AccessRights.READ_WRITE;
    }

    public boolean hasAnyAccess() {
        return accessRights != AccessRights.NONE;
    }

    public void setCookieValue(String cookieValue) {
        this.cookieValue = cookieValue;
    }

    @Override
    public String toString() {
        return "TokenPayload{" +
                "cookieName='" + cookieName + '\'' +
                ", cookieValue='" + cookieValue + '\'' +
                ", applicationId='" + applicationId + '\'' +
                ", versionName='" + versionName + '\'' +
                ", destinationDomain='" + destinationDomain + '\'' +
                ", accessRights='" + accessRights + '\'' +
                ", globalJar='" + globalJar + '\'' +
                '}';
    }
}

