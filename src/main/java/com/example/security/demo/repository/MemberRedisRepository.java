package com.example.security.demo.repository;

import java.util.Optional;

import org.springframework.data.repository.CrudRepository;

import com.example.security.demo.entity.Member;

public interface MemberRedisRepository extends CrudRepository<String, Member> {

	Optional<Member> findByIdAndRole(String id, String role);

}
