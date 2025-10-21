package com.bsep.pki.services;


import com.bsep.pki.dtos.TemplateCreateDTO;
import com.bsep.pki.dtos.TemplateInfoDTO;
import com.bsep.pki.models.Certificate;
import com.bsep.pki.models.CertificateTemplate;
import com.bsep.pki.models.User;
import com.bsep.pki.repositories.CertificateRepository;
import com.bsep.pki.repositories.CertificateTemplateRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.bsep.pki.repositories.UserRepository;
import java.util.List;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class CertificateTemplateService {

    private final CertificateTemplateRepository templateRepository;
    private final CertificateRepository certificateRepository;
    private final UserRepository userRepository;


    @Transactional
    public CertificateTemplate createTemplate(TemplateCreateDTO dto, String ownerEmail) {
        if (templateRepository.findByTemplateName(dto.templateName()).isPresent()) {
            throw new IllegalArgumentException("Template with name '" + dto.templateName() + "' already exists.");
        }

        User owner = userRepository.findByEmail(ownerEmail)
                .orElseThrow(() -> new RuntimeException("Owner not found for email: " + ownerEmail));


        Certificate issuer = certificateRepository.findBySerialNumber(dto.issuerSerialNumber())
                .orElseThrow(() -> new IllegalArgumentException("Issuer with serial number " + dto.issuerSerialNumber() + " not found."));

        if (!issuer.isCa()) {
            throw new IllegalArgumentException("The specified issuer is not a CA and cannot be used in a template.");
        }

        CertificateTemplate template = new CertificateTemplate();
        template.setTemplateName(dto.templateName());
        template.setIssuerSerialNumber(dto.issuerSerialNumber());
        template.setCommonNameRegex(dto.commonNameRegex());
        template.setSanRegex(dto.sanRegex());
        template.setTtlDays(dto.ttlDays());
        template.setKeyUsage(dto.keyUsage());
        template.setExtendedKeyUsage(dto.extendedKeyUsage());
        template.setOwner(owner);

        return templateRepository.save(template);
    }

    @Transactional(readOnly = true)
    public List<TemplateInfoDTO> getTemplatesForUser(String ownerEmail) {
        return templateRepository.findByOwnerEmail(ownerEmail).stream()
                .map(this::mapToDto)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public List<TemplateInfoDTO> getTemplatesForIssuer(String issuerSerialNumber) {
        return templateRepository.findByIssuerSerialNumber(issuerSerialNumber).stream()
                .map(this::mapToDto)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public CertificateTemplate getTemplateById(Long id) {
        return templateRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Template not found with id: " + id));
    }

    private TemplateInfoDTO mapToDto(CertificateTemplate template) {
        return new TemplateInfoDTO(
                template.getId(),
                template.getTemplateName(),
                template.getIssuerSerialNumber(),
                template.getCommonNameRegex(),
                template.getSanRegex(),
                template.getTtlDays(),
                template.getKeyUsage(),
                template.getExtendedKeyUsage()
        );
    }
}