import os
import sys
import yaml
import string
import random
from typing import List
from ldap3 import Server, Connection, SUBTREE, NTLM, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPNoSuchObjectResult
import subprocess
from PyQt5 import QtGui, QtCore
from PyQt5.QtWidgets import  QMainWindow, QMessageBox,QWidget, QDialog
from .ui.MainWindowUi import Ui_MainWindow
# from .ui.LogInUi import Ui_DialogLogIn
from datetime import datetime
import logging
logging.basicConfig(filename='client_application.log', level=logging.DEBUG)
# https://gist.github.com/MalloyDelacroix/2c509d6bcad35c7e35b1851dfc32d161
# todo: сделать поле для указания срока учетной записи / даты блокировки


class RegExpValidator(QtGui.QRegularExpressionValidator):
    validationChanged = QtCore.pyqtSignal(QtGui.QValidator.State)

    def validate(self, input, pos):
        state, input, pos = super().validate(input, pos)
        self.validationChanged.emit(state)
        return state, input, pos

class MainWindow(QMainWindow, Ui_MainWindow):
    def __init__(self,  *args, **kwargs):
        super(MainWindow, self).__init__(*args, **kwargs)
        self.__login = r''
        self.__password = ''
        self.conn = None
        self.makeConnection()
        self.setupUi(self)
        self.addDepatments()
        self._initSignals()
        self.__userName = None
        self.__userSurname = None
        self.__accountDescription = None
        self.__userAccountName = None
        self.__displayName = None
        self.__department = None
        self.__city = None
        self.__accountType = None
        self.__userRank = None
        self.__CN = None
        self.__DN = None
        self.__sex = None
        self.alphabet = {
            'а': 'a',
            'б': 'b',
            'в': 'v',
            'г': 'g',
            'д': 'd',
            'е': 'e',
            'ё': 'e',
            'ж': 'zh',
            'з': 'z',
            'и': 'i',
            'й': 'y',
            'к': 'k',
            'л': 'l',
            'м': 'm',
            'н': 'n',
            'о': 'o',
            'п': 'p',
            'р': 'r',
            'с': 's',
            'т': 't',
            'у': 'u',
            'ф': 'f',
            'х': 'kh',
            'ц': 'ts',
            'ч': 'ch',
            'ш': 'sh',
            'щ': 'SHCH',
            'ъ': '',
            'ы': 'y',
            'ь': '',
            'э': 'e',
            'ю': 'yu',
            'я': 'ya',
        }

    def makeConnection(self):
        AD_SERVER = ''
        AD_USERNAME = self.__login
        AD_USER_PASSWORD = self.__password
        self.conn = Connection(Server(AD_SERVER, use_ssl=True), user=AD_USERNAME, password=(AD_USER_PASSWORD), raise_exceptions=True, authentication=NTLM)
        try:
            self.conn.open()
            self.conn.bind()
        except Exception as e:
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Critical)
            msg.setText("Ошибка")
            msg.setInformativeText(str(e))
            msg.setWindowTitle("Ошибка")
            msg.exec()


    @property
    def getConfig(self):
        with open(os.path.join('services','config.yaml'), encoding='utf8') as f:
            template = yaml.safe_load(f)
        return template


    def _initSignals(self):
        self.pushButtonCreate.clicked.connect(self.createUser)
        self.buttonGroupAccountType.buttonToggled.connect(self.unlockCity)
        self.buttonGroupAccountType.buttonToggled.connect(self.unlockUserRank)
        self.buttonGroupAccountType.buttonToggled.connect(self.unlockAdditionalAccesses)
        self.buttonGroupAccountType.buttonToggled.connect(self.setDefaultAdditionalAccesses)
        self.buttonGroupAccountType.buttonToggled.connect(self.unlockDepartment)
        self.buttonGroupCity.buttonToggled.connect(self.unlockUserRank)
        self.buttonGroupCity.buttonToggled.connect(self.unlockAdditionalAccesses)
        self.buttonGroupCity.buttonToggled.connect(self.setDefaultAdditionalAccesses)
        self.comboBoxDepartment.currentTextChanged.connect(self.setDepartment)
        self.buttonGroupAccountType.buttonToggled.connect(self.setAccountType)
        self.buttonGroupAccountType.buttonToggled.connect(self.validator)
        self.buttonGroupAccountType.buttonToggled.connect(self.unlockLineEdit)
        self.buttonGroupAccountType.buttonToggled.connect(self.unlockSex)



    def validator(self):
        self.lineEditName.setText('')
        self.lineEditSurname.setText('')
        if not self.radioButtonAccountTypeSRV.isChecked():
            nameRegexp = QtCore.QRegularExpression(r'[а-яА-Я]+')
        else:
            nameRegexp = QtCore.QRegularExpression(r'[а-яА-Я]+\w+\d+\s')

        self.nameValidator = RegExpValidator(nameRegexp, self)
        self.lineEditName.setValidator(self.nameValidator)
        self.lineEditSurname.setValidator(self.nameValidator)


    def unlockLineEdit(self):
        self.lineEditSurname.setEnabled(True)
        self.lineEditName.setEnabled(True)
        self.lineEditDescription.setEnabled(True)


    def unlockCity(self):
        '''todo: unlock функции нарушаютр DRY'''
        for i in self.buttonGroupCity.buttons():
            if self.radioButtonAccountTypeEXT.isChecked():
                self.uncheckButtons(self.buttonGroupCity)
                i.setEnabled(False)
            else:
                i.setEnabled(True)


    def unlockUserRank(self):
        for i in self.buttonGroupUserRank.buttons():
            if not(self.radioButtonAccountTypeUSR.isChecked() and (self.radioButtonCitySPB.isChecked() or self.radioButtonCityMSK.isChecked())):
                self.uncheckButtons(self.buttonGroupUserRank)
                i.setEnabled(False)
            else:
                i.setEnabled(True)


    def unlockAdditionalAccesses(self):
        account_type = False
        if self.buttonGroupAccountType.checkedButton():
            account_type = True

        if account_type:
            for i in self.buttonGroupAdditionalAccesses.buttons():
                i.setEnabled(True)


    def unlockSex(self):
        for i in self.buttonGroupSex.buttons():
            if not self.radioButtonAccountTypeUSR.isChecked():
                self.uncheckButtons(self.buttonGroupSex)
                i.setEnabled(False)
            else:
                i.setEnabled(True)

    
    def unlockDepartment(self):
        self.comboBoxDepartment.setCurrentText('')
        if self.radioButtonAccountTypeUSR.isChecked() or self.radioButtonAccountTypeSRV.isChecked():
            self.comboBoxDepartment.setEnabled(True)
        else:
            self.comboBoxDepartment.setEnabled(False)


    def unclockPushButtonCreate(self):
        pass


    def uncheckButtons(self, group, reverse_exclusive=False):
        if reverse_exclusive:
            for i in group.buttons():
                i.setChecked(False)
            group.setExclusive(False)
        else:
            group.setExclusive(False)
            for i in group.buttons():
                i.setChecked(False)
            group.setExclusive(True)


    def addDepatments(self):
        deps =  self.getConfig.get('SERVER').get('DEPARTAMENTS')
        self.comboBoxDepartment.addItems(deps)
        self.comboBoxDepartment.setCurrentText('')


    def ldapSearch(self,  objectCategory : str, sAMAccountName: str, attributes = []):
        if self.conn:
            # value = ''
            # for i in filters:
            #     value += '('+i+'={'+filters[i]+'})'
            #     print(value)

            self.conn.search('dc=,dc=',
                             f'(&(objectCategory={objectCategory})(sAMAccountName={sAMAccountName}))',
                             SUBTREE,
                             attributes=attributes
                             )
            return self.conn.entries


    def setDisplayName(self):
        self.__displayName = None
        self.__displayName = self.__userSurname + ' ' + self.__userName


    def setUserPassword(self, lenght=10):
        self.__userPassword = None
        self.__userPassword = self.createUserPassword(lenght)


    def setUserDescription(self):
        self.__accountDescription = None
        self.__accountDescription = self.lineEditDescription.text().strip()


    def setDepartment(self):
        self.__department = self.comboBoxDepartment.currentText()


    def setAccountType(self):
        self.__accountType = None
        self.__accountType = self.getConfig.get('ATTRIBUTES').get('extensionAttribute15')[self.buttonGroupAccountType.checkedButton().text()]


    def setCity(self):
        if self.buttonGroupCity.checkedButton():
            self.__city = self.getConfig.get('SERVER').get('CITY').get(self.buttonGroupCity.checkedButton().text())


    def setUserRank(self):
        self.__userRank = self.buttonGroupUserRank.checkedButton().text()


    def setDN(self):
        dep = self.__department
        conf_ou = self.getConfig.get('SERVER').get('USERS OU')
        conf_dc = self.getConfig.get('SERVER').get('DC')
        if self.radioButtonAccountTypeSRV.isChecked():
            self.__DN = f'cn={self.__CN},{conf_ou.get("service")},{conf_ou.get(self.__city)},{conf_dc.get("local")}'
        if self.radioButtonAccountTypeUSR.isChecked():
            self.__DN = f'cn={self.__CN},ou={dep},ou=Users,{conf_ou.get(self.__city)},{conf_dc.get("local")}'
        if self.radioButtonAccountTypeEXT.isChecked():
            self.__DN = f'cn={self.__CN},{conf_ou.get("ext")},{conf_dc.get("local")}'


    def setUserSex(self):
        self.__sex = self.buttonGroupSex.checkedButton().text()


    def setDefaultAdditionalAccesses(self):
        if self.radioButtonAccountTypeUSR.isChecked():
            self.checkBoxCreateS4b.setChecked(True)
            self.checkBoxCreateS4b.setEnabled(False)
            self.checkBoxGiveB24.setChecked(True)
            self.checkBoxGiveB24.setEnabled(False)
            self.checkBoxCreateMailBox.setChecked(True)
            self.checkBoxCreateMailBox.setEnabled(False)
        else:
            self.uncheckButtons(self.buttonGroupAdditionalAccesses, reverse_exclusive=True)


    def createUserName(self):
        self.__userName = ''
        name_rus = self.lineEditName.text().strip().lower()
        for i in name_rus:
            self.__userName += self.alphabet.get(i)
        self.__userName = self.__userName.title()
        if name_rus.endswith('ый'):
            self.__userName = self.__userName[:-1].title()


    def createUserSurname(self):
        self.__userSurname  = ''
        surname_rus = self.lineEditSurname.text().strip().lower()
        for i in surname_rus:
            self.__userSurname += self.alphabet.get(i)
        self.__userSurname = self.__userSurname.title()
        if surname_rus.endswith('ый'):
            self.__userSurname = self.__userSurname[:-1].title()


    def createUserAccountName(self):
        sAMAccountName = self.__userName[:1] + self.__userSurname
        for i in range(2, len(self.__userName) + 1):
            if self.ldapSearch(objectCategory='user', sAMAccountName=sAMAccountName):
                sAMAccountName = self.__userName[:i] + self.__userSurname
                print('serach1', self.ldapSearch(objectCategory='user', sAMAccountName=sAMAccountName))
            else:
                self.__userAccountName = sAMAccountName
                break


    def createUserCN(self):
        dep = self.__department
        conf_ou = self.getConfig.get('SERVER').get('USERS OU')
        conf_dc = self.getConfig.get('SERVER').get('DC')
        cn = f'{self.__userSurname} {self.__userName}'
        counter = 2
        if self.radioButtonAccountTypeUSR.isChecked():
            while 1:
                dn = f'cn={cn},ou={dep},ou=Users,{conf_ou.get(self.__city)},{conf_dc.get("local")}'
                try:
                    check = self.conn.search(dn, '(objectclass=user)')
                    if check:
                        cn += str(counter)
                        for i in cn:
                            if i.isdigit():
                                cn = cn.replace(i, '')
                        cn += str(counter)
                        counter += 1
                    else:
                        self.__CN = cn
                        break
                except LDAPNoSuchObjectResult:
                    print(f'CN - {cn} не занято и будет присвоено')
                    self.__CN = cn
                    break


            # if self.radioButtonAccountTypeSRV.isChecked():
            #     dn = f'cn={cn},{conf_ou.get("service")},{conf_ou.get(self.__city)},{conf_dc.get("local")}'
            #
            # if self.radioButtonAccountTypeEXT.isChecked():
            #     dn = f'cn={cn},{conf_ou.get("ext")},{conf_dc.get("local")}'


    def generateRandomString(self, length: int, *choices: str) -> str:
        """Generate a string of a given `length`.

        The result has at least one symbol from each of `choices` if `length` allows.

        Arguments:
            length -- Result string length.
            choices -- Strings with available symbols.
        """
        self.__userPassword = ''
        if not choices:
            choices = (string.ascii_letters,)

        all_choices = "".join(choices)
        result: List[str] = []
        choice_index = 0
        while len(result) < length:
            if choice_index < len(choices):
                symbol = random.choice(choices[choice_index])
                result.append(symbol)
                choice_index += 1
                continue

            symbol = random.choice(all_choices)
            result.append(symbol)

        random.shuffle(result)
        return "".join(result)

    def createUserPassword(self, length: int) -> str:
        """
        Generate a random password for MyDB of a given `length`.

        The result has at least:
        - one uppercase letter
        - one lowercase letter
        - one digit
        - one special character
        """
        return self.generateRandomString(
            length,
            string.ascii_uppercase,
            string.ascii_lowercase,
            string.digits,
        )

    def reset(self):
        # self.__userAccountName
        pass

    def createUser(self):
        self.createUserName()
        self.createUserSurname()
        self.setDepartment()
        self.setUserDescription()
        self.setDisplayName()
        self.setUserPassword()
        self.createUserAccountName()
        self.setUserSex()
        self.setCity()
        self.setUserRank()
        self.createUserCN()
        self.setDN()
        try:
            print(f'{self.__DN}\n{self.__userName}\n{self.__userSurname}\n{self.__userSurname} {self.__userName}\n{self.__userPassword}\n{self.__accountDescription}\n{self.__userAccountName}\n{self.getConfig.get("ATTRIBUTES").get("DIVISION")}\n{self.__department}\n{self.__accountType}')
            self.conn.add(f'{self.__DN}', attributes={
                'objectClass': 'user',
                'givenName' : self.__userName,
                'sn' : self.__userSurname,
                'displayName' : self.__displayName,
                'userPrincipalName' : self.__userAccountName + '@mail.ru',
                'description' : self.__accountDescription,
                'sAMAccountName' : self.__userAccountName,
                'Division': self.getConfig.get('ATTRIBUTES').get('DIVISION'),
                'extensionAttribute14': self.__department,
                'extensionAttribute15': self.__accountType,
            })

            self.setUserAccountPassword()
            self.changeUserAccountControl()
            self.setPoliceGroups()
            self.createEmailBox()
            logging.info(datetime.now())
            print(self.conn.result)
            print(self.conn.response)
        except LDAPNoSuchObjectResult:
            pass
        except Exception as e:
            logging.info(datetime.now())
            logging.exception(e)


    def unlockUserAccont(self):
        self.conn.extend.microsoft.unlock_account(user=self.__DN)


    def changeUserAccountControl(self):
        self.conn.modify({self.__DN}, {'userAccountControl': (MODIFY_REPLACE, [512])})


    def setUserAccountPassword(self):
        self.conn.extend.microsoft.modify_password(user=self.__DN, new_password=self.__userPassword)


    def setPoliceGroups(self):
        all_groups = self.getConfig['POLICY_GPOUPS']
        if self.__accountType == 'USR':
            print('penes')
            try:
                general = all_groups['GENERAL']
                cities = all_groups['CITIES'][self.__city]
                sex = all_groups['SEX'][self.__sex]
                user_rank = all_groups['RANK'][self.__department] + f'{self.__userRank}s'
                usr_groups = []
                for i in [general, cities, sex, user_rank]:
                    if not isinstance(i, list):
                        i = i.split()
                    usr_groups += i
            except Exception as e:
                pass
            print(user_rank)
            print(usr_groups)
            for i in usr_groups:
                objectGUID = self.ldapSearch(objectCategory='group', sAMAccountName=i, attributes=['objectGUID'])
                print(objectGUID)
                _ = str(objectGUID[0].objectGUID)[1:-1]
                objectGUID = f'<GUID={_}>'
                self.conn.extend.microsoft.add_members_to_groups(self.__DN, objectGUID)
        else:
            print('ошибка')

    #тест ps скрипта
    def createEmailBox(self):
        PATH = ''
        command = f"powershell.exe {PATH} $login={self.__login} $pswrd={self.__password}"
        process = subprocess.Popen(command.split(), stdout=sys.stdout)
        result = process.communicate()
        print(result.text())


    def createS4bAccount(self):
        pass



