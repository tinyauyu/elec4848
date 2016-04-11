int current;  //in mA
int val;
int inPin = 7;

void setup() {
  Serial.begin(9600);
  pinMode(inPin, INPUT);
}

void loop() {
  val = digitalRead(inPin);
  if(val==1){
    current = analogRead(0)*(5.0/1023.0) * 1000;
    Serial.println(current);
    delay(100);    
  } else {
    Serial.println(-1);
  }
}
