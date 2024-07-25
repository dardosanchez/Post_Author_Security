package com.todocodeacademy.springsecurity.repository;

import com.todocodeacademy.springsecurity.model.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IPermissionRepository extends JpaRepository<Permission, Long> {

}
