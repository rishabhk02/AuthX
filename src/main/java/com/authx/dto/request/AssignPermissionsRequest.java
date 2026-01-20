package com.authx.dto.request;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AssignPermissionsRequest {
    @NotNull(message = "User ID is required")
    private Long userId;
    
    @NotNull(message = "Permission IDs are required")
    private Set<Long> permissionIds;
}