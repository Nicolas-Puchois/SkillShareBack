<?php

declare(strict_types=1);

namespace App\model;

use DateTime;

class User
{
    private int $id;
    private string $username;
    private string $avatar = "avatar_par_defaut.png";
    private string $email;
    private string $password;
    private array $roles = ["ROLE_USER"];
    private string $created_at;
    private ?string $email_token;
    private bool $is_verified;
    private string $verified_at;

    public function __construct(array $data)
    {
        $this->username = $data['username'];
        $this->email = $data['email'];
        $this->password = $data['password'];
        $this->avatar = $data['avatar'] ?? $this->avatar;
        $this->email_token = $data['email_token'];
        $this->is_verified = isset($data['is_verified']) ? (bool)$data['is_verified'] : false;
    }

    /**
     * Get the value of id
     *
     * @return int
     */
    public function getId(): int
    {
        return $this->id;
    }

    /**
     * Set the value of id
     *
     * @param int $id
     *
     * @return self
     */
    public function setId(int $id): self
    {
        $this->id = $id;
        return $this;
    }

    /**
     * Get the value of username
     *
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * Set the value of username
     *
     * @param string $username
     *
     * @return self
     */
    public function setUsername(string $username): self
    {
        $this->username = $username;
        return $this;
    }

    /**
     * Get the value of avatar
     *
     * @return string
     */
    public function getAvatar(): string
    {
        return $this->avatar;
    }

    /**
     * Set the value of avatar
     *
     * @param string $avatar
     *
     * @return self
     */
    public function setAvatar(string $avatar): self
    {
        $this->avatar = $avatar;
        return $this;
    }

    /**
     * Get the value of email
     *
     * @return string
     */
    public function getEmail(): string
    {
        return $this->email;
    }

    /**
     * Set the value of email
     *
     * @param string $email
     *
     * @return self
     */
    public function setEmail(string $email): self
    {
        $this->email = $email;
        return $this;
    }



    /**
     * Get the value of role
     *
     * @return array
     */
    public function getRoles(): array
    {
        return $this->roles;
    }

    /**
     * Set the value of role
     *
     * @param array $role
     *
     * @return self
     */
    public function setRoles(array $roles): self
    {
        $this->roles = $roles;
        return $this;
    }


    /**
     * Get the value of password
     *
     * @return string
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    /**
     * Set the value of password
     *
     * @param string $password
     *
     * @return self
     */
    public function setPassword(string $password): self
    {
        $this->password = $password;
        return $this;
    }

    /**
     * Get the value of created_at
     *
     * @return string
     */
    public function getCreatedAt(): string
    {
        return $this->created_at;
    }

    /**
     * Set the value of created_at
     *
     * @param string $created_at
     *
     * @return self
     */
    public function setCreatedAt(string $created_at): self
    {
        $this->created_at = $created_at;
        return $this;
    }

    /**
     * Get the value of email_token
     *
     * @return string
     */
    public function getEmailToken(): ?string
    {
        return $this->email_token;
    }

    /**
     * Set the value of email_token
     *
     * @param string $email_token
     *
     * @return self
     */
    public function setEmailToken(?string $email_token): self
    {
        $this->email_token = $email_token;
        return $this;
    }

    /**
     * Get the value of is_verified
     *
     * @return bool
     */
    public function getIsVerified(): bool
    {
        return $this->is_verified;
    }

    /**
     * Set the value of is_verified
     *
     * @param bool $is_verified
     *
     * @return self
     */
    public function setIsVerified(bool $is_verified): self
    {
        $this->is_verified = $is_verified;
        return $this;
    }

    /**
     * Get the value of verified_at
     *
     * @return string
     */
    public function getVerifiedAt(): string
    {
        return $this->verified_at;
    }

    /**
     * Set the value of verified_at
     *
     * @param string $verified_at
     *
     * @return self
     */
    public function setVerifiedAt(string $verified_at): self
    {
        $this->verified_at = $verified_at;
        return $this;
    }
}
