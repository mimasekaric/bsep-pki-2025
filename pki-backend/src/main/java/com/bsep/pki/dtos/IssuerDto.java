package com.bsep.pki.dtos;

import java.util.Date;

public class IssuerDto {

    private String serialNumber;
    private String commonName;
    private Date validFrom;
    private Date validTo;

    public IssuerDto() {
    }

    public IssuerDto(String serialNumber, String commonName, Date validFrom, Date validTo) {
        this.serialNumber = serialNumber;
        this.commonName = commonName;
        this.validFrom = validFrom;
        this.validTo = validTo;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public Date getValidFrom() {
        return validFrom;
    }

    public void setValidFrom(Date validFrom) {
        this.validFrom = validFrom;
    }

    public Date getValidTo() {
        return validTo;
    }

    public void setValidTo(Date validTo) {
        this.validTo = validTo;
    }
}