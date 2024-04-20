from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from whois import whois
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
import os
import platform

system_name = platform.system()

# tải các gói cần thiết nếu chưa có
class InstallPackage:
    def install(self, path_pip):
        install_command = f"{path_pip} install selenium webdriver-manager python-whois scikit-learn numpy"
        os.system(str(install_command))
        try:
            from webdriver_manager.chrome import ChromeDriverManager
            print(ChromeDriverManager().install())
        except:
            return "đã có lỗi khi tải chrome driver"


# lấy thông tin tên miền
class GetDomainInfo:
    def __init__(self, tlds=["net", "com"]):
        self.tlds = tlds

    def domain_information(self, domain):
        try:
            domain_infomations = whois(domain)
        except:
            return "error"
        
        keys = ["domain_name", "registrar", "whois_server", "referral_url", "updated_date", "creation_date",
                "expiration_date", "name_servers", "status", "emails", "dnssec", "name", "org", "address",
                "city", "state", "registrant_postal_code", "country"]
        update_domain_infomation = ""
        for key in keys:
            update_domain_infomation += str(f"{domain_infomations[key]}, ")
        for tld in self.tlds:
            if domain.split(".")[1] in tld:
                update_domain_infomation = update_domain_infomation+tld
                break
        return update_domain_infomation
    

# tìm tên miền
class DomainFinding:
    def __init__(self, path_log="log.txt", tlds=["net", "com"]):
        assert isinstance(tlds, list), "chúng tôi cần 1 danh sách chứa các .net hoặc .com để phân loại"
        self.path_log = path_log
        self.tlds = tlds

    def setup_browser(self):
        option = Options()
        option.add_argument("--log-level=3")
        option.add_argument("--headless")
        browser = webdriver.Chrome(options=option)
        os.system("cls") if system_name in "Windows" else os.system("clear")
        return browser
    
    def finding_domain(self):
        browser = self.setup_browser()
        # giới hạn các phiên chạy và lưu lại các domain và thông tin của nó
        domains, uptimes = [], []
        for i in range(20):
            try:
                browser.get("https://emailfake.com/fake_email_generator")
                email = WebDriverWait(browser, 10).until(EC.presence_of_element_located((By.XPATH, '//*[@id="email_ch_text"]'))).text
                domain = email.split("@")[1]

                uptime_text = WebDriverWait(browser, 10).until(EC.presence_of_element_located((By.XPATH, '//*[@id="checkdomainset"]'))).text
                uptime = uptime_text.split()[4]

                domains.append(domain)
                uptimes.append(uptime)

                print(f"{i+1} - {domain} - {uptime} days")

            except Exception as e:
                print(f"mã lỗi: {e}")
                browser.quit()
                return domains, uptimes
            
        browser.quit()
        return domains, uptimes
    
    # kiểm tra tên miền có tồn tại trong logs hay không
    def check_log(self, domain):
        with open(self.path_log, mode="r", encoding='utf-8', errors="ignore") as file:
            data_logs = file.read().splitlines()
        if domain not in data_logs:
            return True
        else:
            return False
        
    # kiểm tra đuôi của tên miền
    def check_tld(self, domain):
        if domain.split(".")[1] in self.tlds:
            return True
        else:
            return False
    
    # kiểm tra thời gian tạo của tên miền
    def check_uptime(self, uptime):
        if int(uptime) <= 7:
            return True
        else:
            return False
        
    # lưu domain vào log
    def save_log(self, domain):
        with open(self.path_log, mode="a", encoding='utf-8', errors="ignore") as file:
            file.write(domain+"\n")
    
    # lọc các tên miền đã thu thập
    def get_domains(self):
        domains, uptimes = self.finding_domain()
        good_domain_filtered, bad_domain_filtered = [], []
        for i in range(len(domains)):
            check_log = self.check_log(domain=domains[i])
            check_tld = self.check_tld(domain=domains[i])
            check_uptime = self.check_uptime(uptime=uptimes[i])
            if check_log == True and check_tld == True and check_uptime == True:
                self.save_log(domain=domains[i])
                good_domain_filtered.append(domains[i])
            else:
                bad_domain_filtered.append(domains[i])
        return good_domain_filtered, bad_domain_filtered
    

# dự đoán tên miền
class PredictDomain:
    def __init__(self, path_train="train.txt"):
        self.path_train = path_train
    
    def read_train(self):
        X_train, y_train = [], []
        with open(self.path_train, "r", encoding="utf-8") as file:
            data = file.read().splitlines()
            for info in data:
                X_train.append(info.split(" - ")[0])
                y_train.append(info.split(" - ")[1])
        return [X_train], y_train
    
    def predict(self, domain):
        domain_info = GetDomainInfo().domain_information(domain=domain)
        X_train, y_train = self.read_train()
        bow_transformer = CountVectorizer()
        X_train = bow_transformer.fit_transform(X_train[0]).toarray()
        desicion_tree = DecisionTreeClassifier()
        random_forest = RandomForestClassifier()
        bayes_model = GaussianNB()
        svm_model = SVC(probability=True)
        knn_model = KNeighborsClassifier(n_neighbors=3)
        voting_model = VotingClassifier(estimators=[("desicion tree", desicion_tree),
                                                    ("random forest", random_forest),
                                                    ("svm", svm_model),
                                                    ("knn", knn_model),
                                                    ("bayes", bayes_model)], voting="soft")
        voting_model.fit(X_train, y_train)
        X_test = bow_transformer.transform([domain_info]).toarray()
        predict = voting_model.predict(X_test)
        return predict[0]
    

# lưu trữ tên miền đã tìm và dự đoán
class StorageDomain:
    def __init__(self, path_save=None):
        self.path_save = path_save
    
    def save_domain(self, domain, clsf: int):
        if self.path_save is None:
            with open("saved.txt", mode="a", encoding="utf-8") as file:
                file.write(f"{domain} : {clsf}\n")
        else: 
            with open(self.path_save, mode="a", encoding="utf-8") as file:
                file.write(f"{domain} : {clsf}\n")

    
# dùng các tập lệnh để tạo ra 1 step hoàn chỉnh để chạy tool
class RunTool:
    def __init__(self, path_save=None, path_train="train.txt", path_log="log.txt", tlds=["net", "com"]):
        self.path_train = path_train
        self.path_log = path_log
        self.tlds = tlds
        self.path_save = path_save

    def run(self):
        good_domain, bad_domain = DomainFinding(path_log=self.path_log, tlds=self.tlds).get_domains()
        for domain in good_domain:
            domain_info = GetDomainInfo(tlds=self.tlds).domain_information(domain=domain)
            if domain_info in "error":
                continue
            domain_pred = PredictDomain(path_train=self.path_train).predict(domain=domain_info)
            if domain_pred in "1":
                StorageDomain(path_save=self.path_save).save_domain(domain=domain, clsf=1)
            else:
                StorageDomain(path_save=self.path_save).save_domain(domain=domain, clsf=0)

class TrainingToolPredict:
    def __init__(self, path_train="train.txt", tlds=["net", "com"]):
        self.path_train = path_train
        self.tlds = tlds

    def save_train(self, train_info, binary_clsf):
        with open(self.path_train, mode="a", encoding="utf-8") as file:
            file.write(f"{train_info} - {binary_clsf}\n")
    
    def clasify_via_chatui(self):
        while True:
            inp_domain = input("nhập vào đây tên miền mà bạn muốn training : ").lower().strip()
            if inp_domain.split(".")[1] not in self.tlds:
                print(f"xin hãy nhập tên miền hợp lệ đúng với các tlds sau {self.tlds}")
                continue
            inp_clsf = input("nhập vào đây 1 / 0 : ")
            if inp_clsf not in ["1", "0"]:
                os.system("cls") if system_name in "Windows" else os.system("clear") 
                print("vui lòng nhập số phân loại hợp lệ để training (1 hoặc 0)")
                continue
            
            train_info = GetDomainInfo().domain_information(inp_domain)

            try:
                self.save_train(train_info=train_info, binary_clsf=inp_clsf)
            except:
                input("tên file train không hợp lệ vui lòng xem lại ạ, enter để bỏ qua <_| : ")

            os.system("cls") if system_name in "Windows" else os.system("clear") 
            print("cảm ơn bạn đã cho tôi biết, tôi sẽ tốt hơn nhờ lần dạy này, tôi đã nhận được rồi nhé <3")


class PredictDomainByDomain:
    def __init__(self, path_train, tlds):
        self.tlds = tlds
        self.path_train = path_train

    def predict(self):
        print("xin chào bạn bạn có thể dùng tôi để dự đoán từng domain lẻ tại đây ^.^")
        while True:
            inp = input("nhập domain mà bạn muốn dự đoán : ").lower().strip()
            try:
                if inp.split(".")[1] not in self.tlds:
                    os.system("cls") if system_name in "Windows" else os.system("clear") 
                    print("vui lòng nhập tên miền có trong giới hạn của tlds", 
                          f" đây là giới hạn mà mô hình đã được đào tạo : {self.tlds}")
                    continue
            except:
                os.system("cls") if system_name in "Windows" else os.system("clear") 
                print("vui lòng nhập tên miền hợp lệ đi ạ")
                continue
            predict_result = PredictDomain(path_train=self.path_train).predict(domain=inp)
            os.system("cls") if system_name in "Windows" else os.system("clear") 
            print(f"kết quả dự đoán : {predict_result}")

class CommandUiChatQality:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def predict(self, inputs):
        random_forest = RandomForestClassifier()
        bow_transformer = CountVectorizer()
        X_train = bow_transformer.fit_transform(self.x[0]).toarray()
        random_forest.fit(X_train, y=self.y)
        X_test = bow_transformer.transform(inputs)
        y_pred = random_forest.predict(X_test)
        return y_pred[0]
    

# dữ liệu train cho mô hình chat nhận diện lệnh
user_command = [["1", "tôi muốn chạy tool","chạy tool", "run tool đi", "kích hoạt tool",
                "bật đào tạo", "đào tạo bạn", "training", "2",
                "tải gói", "install package", "tải", "tải gói cho tool",
                "dự đoán tên miền", "dự đoán tên miền lẻ", "dự đoán miền", "đoán domain"]]

predict_command = ["run tool", "run tool", "run tool", "run tool", "run tool",
             "training", "training", "training", "training",
             "install pack", "install pack", "install pack", "install pack",
              "domain predict", "domain predict", "domain predict", "domain predict"]


path_log = "log.txt"
path_save = "saved.txt"
path_train = "train.txt"
tlds = ["net", "com"]

if os.path.exists(path=path_log) and os.path.exists(path=path_save) and os.path.exists(path=path_train) == False:
    print("chưa có các file cần thiết, tiến hành tạo ...")
    for path in [path_log, path_save, path_train]:
        with open(path, mode="a"):
            continue
else:
    print("đã có đầy đủ file cần thiết")

# giao diện dòng lệnh
def command_ui():
    print("\n* lưu ý: train cho ireland\n- chạy tool\n- training cho nó\n- tải gói để chạy")
    print("- dự đoán tên miền\n")
    inp = input("chọn 1 trong những lựa chọn trên : ")

    cm_pred = CommandUiChatQality(x=user_command, y=predict_command).predict([inp])
    print(f"đã hiểu, bạn muốn : {cm_pred}\n")

    if cm_pred in "run tool":
        
        # vòng lặp lòng tự động xóa tham chiếu giảm tải máy
        while True:
            try:
                for _ in range(100):
                    run_tool = RunTool(path_log=path_log, path_save=path_save, path_train=path_train, tlds=tlds)
                    run_tool.run()
                del(run_tool, _)
            except:
                continue

    elif cm_pred in "training":
        TrainingToolPredict().clasify_via_chatui()
    
    elif cm_pred in "install pack":
        while True:
            inp = input("nhập lệnh pip để tải hoặc nhấn hủy để quay lại : ")
            if inp in "hủy":
                os.system("cls") if system_name in "Windows" else os.system("clear") 
                break
            try:
                print(InstallPackage().install(inp))
            except:
                print("đã có lỗi từ lệnh pip hoặc lỗi nhập đầu vào của bạn")
                continue
    
    elif cm_pred in "domain predict":
        PredictDomainByDomain(tlds=tlds, path_train=path_train).predict()

while True:
    command_ui()
