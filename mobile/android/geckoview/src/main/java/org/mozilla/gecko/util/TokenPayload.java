package org.mozilla.gecko.util;

import androidx.annotation.Nullable;

public final class TokenPayload {
    public final String cookieName;
    public final @Nullable String cookieValue;      // null if wildcard
    public final String applicationId;
    public final String versionName;
    public final String destinationDomain;
    public final AccessRights accessRights;
    public final boolean globalJar;

    public enum AccessRights {
        NONE,           // Token gewährt keine Berechtigung
        READ,           // Nur Lesen erlaubt
        WRITE,          // Nur Schreiben erlaubt
        READ_WRITE      // Lesen und Schreiben erlaubt
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

    @Override
    public String toString() {
        return "TokenPayload{" +
                "cookieName='" + cookieName + '\'' +
                ", cookieValue='" + cookieValue + '\'' +
                ", applicationId='" + applicationId + '\'' +
                ", versionName='" + versionName + '\'' +
                ", destinationDomain='" + destinationDomain + '\'' +
                ", accessRights=" + accessRights +
                ", globalJar=" + globalJar +
                '}';
    }
}

