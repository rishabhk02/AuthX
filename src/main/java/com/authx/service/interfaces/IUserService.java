package com.authx.service.interfaces;

import com.authx.dto.request.AssignPermissionsRequest;
import com.authx.dto.request.AssignRolesRequest;
import com.authx.dto.response.UserDetailsResponse;

/**
 * User Service Interface
 */
public interface IUserService {
    
    UserDetailsResponse assignRolesToUser(AssignRolesRequest request);
    
    UserDetailsResponse assignPermissionsToUser(AssignPermissionsRequest request);
    
    UserDetailsResponse getUserDetails(Long userId);
}
