package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// 测试现有哈希对应的密码
	hash := "$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi"
	
	// 测试常见密码
	passwords := []string{"123456", "secret", "password", "admin", "test", "123"}
	
	fmt.Println("测试哈希:", hash)
	fmt.Println("哈希长度:", len(hash))
	fmt.Println()
	
	for _, pwd := range passwords {
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(pwd))
		if err == nil {
			fmt.Printf("✅ 匹配成功! 密码是: %s\n", pwd)
		} else {
			fmt.Printf("❌ 密码 '%s' 不匹配\n", pwd)
		}
	}
	
	fmt.Println()
	fmt.Println("生成新的123456哈希:")
	newHash, err := bcrypt.GenerateFromPassword([]byte("123456"), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("生成哈希失败:", err)
		return
	}
	fmt.Println(string(newHash))
	fmt.Println("新哈希长度:", len(string(newHash)))
}
