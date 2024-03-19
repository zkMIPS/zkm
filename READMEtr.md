# ZKM

ZKM, [Plonky2](https://github.com/0xPolygonZero/plonky2) ve [MIPS mikro mimarisi](https://en.wikipedia.org/wiki/MIPS_architecture) tabanlı, Ethereum'u Küresel Uzlaşma Katmanı olarak güçlendiren genel doğrulanabilir bir bilgi işlem altyapısıdır.

# Oluşturma

Uygulamayı oluşturmak için zkm en son sürüm günlük araç zincirine ihtiyaç duyar. Sadece zkm dizininde `cargo build --release` komutunu çalıştırın.

# Örnekleri çalıştırma

Baştan sona bir örnek [examples](./examples) içinde sunulmuştur.

# Dışarıdan katkıda bulunanlar için kılavuz

Her türlü dış katkı teşvik edilmekte ve memnuniyetle karşılanmaktadır!

## PR ınız için genel rehberlik

* PR bir hatayı düzeltir
PR açıklamasında, lütfen hatayı, nasıl yeniden üretileceğini, aldığınız hatayı/istisnayı ve PR'nizin hataları nasıl düzelttiğini açıkça ama kısaca açıklayın.

* PR yeni bir özelliği hizmete sunar

PR açıklamasında, lütfen açıkça ama kısaca şunları tanımlayın

> 1. Özelliğin ne işe yaradığı
> 2. Uygulamak için izlenen yaklaşım
> 3. Yeni özellikler için tüm PR'ler uygun bir test paketi içermelidir.

* PR performansı artırır

Yanlış sonuçları filtrelemeye yardımcı olmak için, bir performans iyileştirmesine yönelik PR açıklaması aşağıdakileri açıkça tanımlamalıdır

> 1. Hedef sorun (kafa karışıklığını önlemek için her PR için yalnızca bir tane!)
> 2. Performansın nasıl ölçüldüğü
> 3. Kullanılan makinenin özellikleri (CPU, OS, uygunsa parçacık sayısı) PR öncesi ve sonrası performans

# Lisanslar

ZKM, MIT lisansı koşulları altında dağıtılmaktadır.

# Güvenlik

Bu kod henüz denetlenmemiştir ve herhangi bir ürün sisteminde kullanılmamalıdır.
